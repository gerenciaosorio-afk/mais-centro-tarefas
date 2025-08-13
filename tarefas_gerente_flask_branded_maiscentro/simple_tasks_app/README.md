
# Tarefas da Gerente (Flask) — Mais Centro Clínico

Site simples para que a equipe crie **tarefas para a gerente** (somente a gerente conclui/exclui).

## Como rodar

1) Python 3.10+ instalado.  
2) No terminal, dentro da pasta do projeto:
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```
3) Acesse http://localhost:5000

**Gerente inicial (trocar depois):**
- E-mail: admin@clinica.com
- Senha: admin123

## Branding aplicado
- Logo já embutida em `static/logo.png` e **favicon** em `static/favicon.ico`.
- Nome padrão: **Mais Centro Clínico** (pode mudar definindo `CLINIC_NAME`).
- Cores extraídas do logo:
  - Primária: `#12999D`
  - Acento: `#0E777A`

Para alterar o nome exibido:
- Windows (PowerShell): `set CLINIC_NAME="Mais Centro Clínico"`
- macOS/Linux (bash): `export CLINIC_NAME="Mais Centro Clínico"`

Para ajustar cores manualmente, edite `static/styles.css`.
