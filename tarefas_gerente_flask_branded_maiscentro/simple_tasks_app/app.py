import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, abort, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import csv
from io import StringIO

# -------------------- Config --------------------
app = Flask(__name__)

# Saúde para Render
@app.route("/healthz")
def healthz():
    return "ok", 200

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "troque-esta-chave")
db_url = os.environ.get("DATABASE_URL")
if db_url:
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///tasks.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Branding
app.config["CLINIC_NAME"] = os.environ.get("CLINIC_NAME", "Mais Centro Clínico")

# Conexão resiliente (útil no Render/Neon)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
    "pool_size": 5,
    "max_overflow": 0,
}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

@app.context_processor
def inject_branding():
    logo_path = os.path.join(app.static_folder, "logo.png")
    fav_path = os.path.join(app.static_folder, "favicon.ico")
    return dict(
        CLINIC_NAME=app.config.get("CLINIC_NAME", "Mais Centro Clínico"),
        logo_exists=os.path.exists(logo_path),
        favicon_exists=os.path.exists(fav_path)
    )

# -------------------- Models --------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="staff")  # "manager" ou "staff"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="pendente")  # "pendente" | "concluida"
    observation = db.Column(db.Text, nullable=True)       # observação do gerente
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.Date, nullable=True)

    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_by = db.relationship("User", foreign_keys=[created_by_id])
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    assigned_to = db.relationship("User", foreign_keys=[assigned_to_id])

# -------------------- Helpers --------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def manager_required():
    if not current_user.is_authenticated or current_user.role != "manager":
        abort(403)

def get_manager_user():
    return User.query.filter_by(role="manager").first()

def get_managers():
    return User.query.filter_by(role="manager").order_by(User.name.asc()).all()

def get_users():
    return User.query.order_by(User.name.asc()).all()

# -------------------- Setup inicial (Flask 3) --------------------
def init_db():
    db.create_all()
    if not User.query.filter_by(role="manager").first():
        admin = User(name="Gerente", email="admin@clinica.com", role="manager")
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()

with app.app_context():
    init_db()

# -------------------- Autenticação --------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("tasks"))
        flash("Credenciais inválidas.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    # se veio com ?as_manager=1 na URL, ou no POST oculto
    as_manager = (request.args.get("as_manager") == "1") or (request.form.get("as_manager") == "1")

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Preencha todos os campos.", "danger")
            return render_template("register.html", as_manager=as_manager, name=name, email=email)

        if User.query.filter_by(email=email).first():
            flash("E-mail já cadastrado.", "warning")
            return render_template("register.html", as_manager=as_manager, name=name, email=email)

        role = "staff"
        if as_manager:
            # criar gerente exige MANAGER_INVITE_CODE correto
            code = (request.form.get("manager_code") or "").strip()
            if not MANAGER_INVITE_CODE:
                flash("Cadastro de gerência está desabilitado (sem código configurado).", "warning")
                return render_template("register.html", as_manager=as_manager, name=name, email=email)
            if code != MANAGER_INVITE_CODE:
                flash("Código de convite inválido.", "danger")
                return render_template("register.html", as_manager=as_manager, name=name, email=email)
            role = "manager"

        user = User(name=name, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Cadastro realizado! Você já pode entrar.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", as_manager=as_manager)

# -------------------- Perfil (usuário edita o próprio nome) --------------------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("O nome não pode ficar vazio.", "danger")
        else:
            current_user.name = name
            db.session.commit()
            flash("Seu nome foi atualizado!", "success")
            return redirect(url_for("tasks"))
    return render_template("profile.html")

# -------------------- Usuárias (apenas gerente) --------------------
@app.route("/users")
@login_required
def users_list():
    manager_required()
    users = User.query.order_by(User.role.desc(), User.name.asc()).all()
    return render_template("users.html", users=users)

@app.route("/users/new", methods=["GET", "POST"])
@login_required
def users_new():
    manager_required()
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()
        role = (request.form.get("role") or "staff").strip()
        if role not in ("manager", "staff"):
            role = "staff"

        if not name or not email or not password:
            flash("Preencha nome, e-mail e senha.", "danger")
            return render_template("user_form.html", mode="new")

        if User.query.filter_by(email=email).first():
            flash("E-mail já cadastrado.", "warning")
            return render_template("user_form.html", mode="new")

        u = User(name=name, email=email, role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("Usuária criada com sucesso.", "success")
        return redirect(url_for("users_list"))

    return render_template("user_form.html", mode="new")

@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def users_edit(user_id):
    manager_required()
    u = User.query.get_or_404(user_id)

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        role = (request.form.get("role") or u.role).strip()
        new_password = (request.form.get("new_password") or "").strip()

        if role not in ("manager", "staff"):
            role = u.role

        if not name or not email:
            flash("Nome e e-mail são obrigatórios.", "danger")
            return render_template("user_form.html", mode="edit", user=u)

        # checa se email já é de outra pessoa
        exists = User.query.filter(User.email == email, User.id != u.id).first()
        if exists:
            flash("E-mail em uso por outra conta.", "warning")
            return render_template("user_form.html", mode="edit", user=u)

        # impedir remover o último gerente
        if u.role == "manager" and role == "staff":
            total_mgrs = User.query.filter_by(role="manager").count()
            if total_mgrs <= 1:
                flash("Não é possível remover o último gerente.", "warning")
                return render_template("user_form.html", mode="edit", user=u)

        u.name = name
        u.email = email
        u.role = role
        if new_password:
            u.set_password(new_password)

        db.session.commit()
        flash("Usuária atualizada.", "success")
        return redirect(url_for("users_list"))

    return render_template("user_form.html", mode="edit", user=u)

@app.route("/users/<int:user_id>/make_manager", methods=["POST"])
@login_required
def make_manager(user_id):
    manager_required()
    u = User.query.get_or_404(user_id)
    u.role = "manager"
    db.session.commit()
    flash(f"{u.name} agora é gerente.", "success")
    return redirect(url_for("users_list"))

@app.route("/users/<int:user_id>/make_staff", methods=["POST"])
@login_required
def make_staff(user_id):
    manager_required()
    u = User.query.get_or_404(user_id)
    if User.query.filter_by(role="manager").count() <= 1 and u.role == "manager":
        flash("Não é possível remover o último gerente.", "warning")
        return redirect(url_for("users_list"))
    u.role = "staff"
    db.session.commit()
    flash(f"{u.name} agora é funcionária.", "success")
    return redirect(url_for("users_list"))

# -------------------- Tarefas --------------------
@app.route("/")
@login_required
def home():
    return redirect(url_for("tasks"))

@app.route("/tasks")
@login_required
def tasks():
    status = request.args.get("status")
    assigned_to_id = request.args.get("assigned_to_id", type=int)

    q = Task.query.order_by(Task.created_at.desc())

    # Funcionária: vê apenas o que ela criou
    if current_user.role != "manager":
        q = q.filter(Task.created_by_id == current_user.id)
        managers = None
    else:
        # Gerente pode filtrar por destinatário (apenas gerentes no filtro)
        if assigned_to_id:
            q = q.filter(Task.assigned_to_id == assigned_to_id)
        managers = get_managers()

    if status in ("pendente", "concluida"):
        q = q.filter(Task.status == status)

    items = q.all()
    return render_template("tasks.html",
                           tasks=items,
                           status=status,
                           managers=managers,
                           assigned_to_id=assigned_to_id)

@app.route("/tasks/new", methods=["GET", "POST"])
@login_required
def create_task():
    managers = get_managers()
    users = get_users() if current_user.role == "manager" else None

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = (request.form.get("description", "") or "").strip() or None
        due = (request.form.get("due_date", "") or "").strip()
        from datetime import datetime as dt
        due_date = dt.strptime(due, "%Y-%m-%d").date() if due else None

        assigned_to = None
        assigned_to_id = request.form.get("assigned_to_id")
        if assigned_to_id:
            assigned_to = User.query.get(int(assigned_to_id))

        # Regras:
        # - Gerente pode atribuir para QUALQUER usuário.
        # - Funcionária só pode atribuir para GERENTE (fallback para algum gerente).
        if current_user.role != "manager":
            if not assigned_to or assigned_to.role != "manager":
                assigned_to = get_manager_user()
        else:
            if not assigned_to:
                assigned_to = current_user

        if not title:
            flash("Título é obrigatório.", "danger")
            return render_template("task_form.html",
                                   managers=managers, users=users,
                                   default_assigned_id=(assigned_to.id if assigned_to else None))

        if not assigned_to:
            flash("Nenhum destinatário válido encontrado.", "danger")
            return render_template("task_form.html", managers=managers, users=users)

        task = Task(
            title=title,
            description=description,
            created_by=current_user,
            assigned_to=assigned_to,
            due_date=due_date,
        )
        db.session.add(task)
        db.session.commit()
        flash("Tarefa criada!", "success")
        return redirect(url_for("tasks"))

    default_assigned = current_user if current_user.role == "manager" else get_manager_user()
    return render_template(
        "task_form.html",
        managers=managers,
        users=users,
        default_assigned_id=default_assigned.id if default_assigned else None,
    )

@app.route("/tasks/<int:task_id>/done", methods=["POST"])
@login_required
def set_done(task_id):
    if current_user.role != "manager":
        abort(403)
    task = Task.query.get_or_404(task_id)
    task.status = "concluida"
    db.session.commit()
    flash("Tarefa marcada como concluída.", "success")
    return redirect(url_for("tasks"))

@app.route("/tasks/<int:task_id>/reopen", methods=["POST"])
@login_required
def reopen(task_id):
    if current_user.role != "manager":
        abort(403)
    task = Task.query.get_or_404(task_id)
    task.status = "pendente"
    db.session.commit()
    flash("Tarefa reaberta.", "success")
    return redirect(url_for("tasks"))

@app.route("/tasks/<int:task_id>/obs", methods=["POST"])
@login_required
def update_observation(task_id):
    if current_user.role != "manager":
        abort(403)
    task = Task.query.get_or_404(task_id)
    observation = request.form.get("observation", "").strip() or None
    task.observation = observation
    db.session.commit()
    flash("Observação salva.", "success")
    return redirect(url_for("tasks"))

@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id):
    if current_user.role != "manager":
        abort(403)
    task = Task.query.get_or_404(task_id)
    db.session.delete(task)
    db.session.commit()
    flash("Tarefa excluída.", "info")
    return redirect(url_for("tasks"))

@app.route("/tasks/export.csv")
@login_required
def export_tasks_csv():
    status = request.args.get("status")
    assigned_to_id = request.args.get("assigned_to_id", type=int)

    q = Task.query.order_by(Task.created_at.desc())

    if current_user.role != "manager":
        q = q.filter(Task.created_by_id == current_user.id)
    else:
        if assigned_to_id:
            q = q.filter(Task.assigned_to_id == assigned_to_id)

    if status in ("pendente", "concluida"):
        q = q.filter(Task.status == status)

    rows = q.all()
    buf = StringIO()
    writer = csv.writer(buf, delimiter=";", lineterminator="\n")
    writer.writerow([
        "ID", "Título", "Descrição", "Status", "Observação",
        "Criada em", "Vence em", "Criada por", "Atribuída a"
    ])
    for t in rows:
        writer.writerow([
            t.id, t.title, t.description or "", t.status, t.observation or "",
            t.created_at.strftime("%Y-%m-%d %H:%M"),
            t.due_date.strftime("%Y-%m-%d") if t.due_date else "",
            t.created_by.name if t.created_by else "",
            t.assigned_to.name if t.assigned_to else "",
        ])
    data = buf.getvalue().encode("utf-8-sig")
    filename = f"tarefas_{status or 'todas'}.csv"
    return Response(
        data,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# -------------------- Troca de senha --------------------
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if not current_user.check_password(current):
            flash("Senha atual incorreta.", "danger")
        elif len(new) < 8:
            flash("A nova senha deve ter pelo menos 8 caracteres.", "warning")
        elif new != confirm:
            flash("Confirmação diferente da nova senha.", "warning")
        else:
            current_user.set_password(new)
            db.session.commit()
            flash("Senha alterada com sucesso!", "success")
            return redirect(url_for("tasks"))
    return render_template("change_password.html")

# -------------------- Exec --------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
