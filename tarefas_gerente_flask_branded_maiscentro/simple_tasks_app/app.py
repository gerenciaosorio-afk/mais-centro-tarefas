
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
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "troque-esta-chave")
db_url = os.environ.get("DATABASE_URL")
if db_url:
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///tasks.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ---- Branding (nome da clínica via variável de ambiente) ----
app.config["CLINIC_NAME"] = os.environ.get("CLINIC_NAME", "Mais Centro Clínico")

# ✅ CONEXÃO RESILIENTE (coloque antes do db = SQLAlchemy(app))
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,   # testa a conexão antes de usar
    "pool_recycle": 280,     # recicla conexões antigas
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
    observation = db.Column(db.Text, nullable=True)  # anotação/observação do gerente
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
    # Retorna o primeiro usuário gerente
    return User.query.filter_by(role="manager").first()

# -------------------- Setup inicial (compatível com Flask 3) --------------------
def init_db():
    db.create_all()
    if not User.query.filter_by(role="manager").first():
        admin = User(name="Gerente", email="admin@clinica.com", role="manager")
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()

with app.app_context():
    init_db()

# -------------------- Rotas de Autenticação --------------------
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
    # Registro aberto cria sempre 'staff'. O gerente pode trocar o papel via SQL se precisar.
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or not password:
            flash("Preencha todos os campos.", "danger")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("E-mail já cadastrado.", "warning")
            return render_template("register.html")
        user = User(name=name, email=email, role="staff")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Cadastro realizado! Você já pode entrar.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

# -------------------- Rotas de Tarefas --------------------
@app.route("/")
@login_required
def home():
    return redirect(url_for("tasks"))

@app.route("/tasks")
@login_required
def tasks():
    status = request.args.get("status")
    q = Task.query.order_by(Task.created_at.desc())

    # se não for gerente, mostra só as tarefas criadas pela usuária logada
    if current_user.role != "manager":
        q = q.filter(Task.created_by_id == current_user.id)

    if status in ("pendente", "concluida"):
        q = q.filter_by(status=status)

    items = q.all()
    return render_template("tasks.html", tasks=items, status=status)

@app.route("/tasks/new", methods=["GET", "POST"])
@login_required
def create_task():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip() or None
        due = request.form.get("due_date", "").strip()
        from datetime import datetime as dt
        due_date = dt.strptime(due, "%Y-%m-%d").date() if due else None

        if not title:
            flash("Título é obrigatório.", "danger")
            return render_template("task_form.html")

        manager = get_manager_user()
        task = Task(
            title=title,
            description=description,
            created_by=current_user,
            assigned_to=manager,
            due_date=due_date,
        )
        db.session.add(task)
        db.session.commit()
        flash("Tarefa criada para o gerente.", "success")
        return redirect(url_for("tasks"))
    return render_template("task_form.html")

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

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        # validações simples
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

@app.route("/tasks/export.csv")
@login_required
def export_tasks_csv():
    status = request.args.get("status")
    q = Task.query.order_by(Task.created_at.desc())

    # se não for gerente, exporta apenas as tarefas criadas pela usuária logada
    if current_user.role != "manager":
        q = q.filter(Task.created_by_id == current_user.id)

    if status in ("pendente", "concluida"):
        q = q.filter_by(status=status)

    rows = q.all()

    # Usar ; (padrão pt-BR) e BOM para abrir bonito no Excel
    buf = StringIO()
    writer = csv.writer(buf, delimiter=";", lineterminator="\n")
    writer.writerow([
        "ID", "Título", "Descrição", "Status", "Observação",
        "Criada em", "Vence em", "Criada por", "Atribuída a"
    ])
    for t in rows:
        writer.writerow([
            t.id,
            t.title,
            t.description or "",
            t.status,
            t.observation or "",
            t.created_at.strftime("%Y-%m-%d %H:%M"),
            t.due_date.strftime("%Y-%m-%d") if t.due_date else "",
            t.created_by.name if t.created_by else "",
            t.assigned_to.name if t.assigned_to else "",
        ])

    data = buf.getvalue().encode("utf-8-sig")  # BOM p/ Excel
    filename = f"tarefas_{status or 'todas'}.csv"
    return Response(
        data,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# -------------------- Exec --------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
