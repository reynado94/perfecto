import os
import sqlite3
import smtplib
from flask import Flask, render_template, request, redirect, url_for, session, flash
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash, check_password_hash
from random import randint

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# Configuración del correo desde variables de entorno
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

def get_db_connection():
    """Establece una conexión a la base de datos y maneja errores."""
    try:
        conn = sqlite3.connect('inventory.db')
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"Error al conectar con la base de datos: {e}")
        return None

def init_db():
    """Inicializa la base de datos creando tablas si no existen."""
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                          id INTEGER PRIMARY KEY AUTOINCREMENT, 
                          username TEXT UNIQUE NOT NULL, 
                          password TEXT NOT NULL,
                          reset_token TEXT)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS products (
                          id INTEGER PRIMARY KEY AUTOINCREMENT, 
                          user_id INTEGER NOT NULL, 
                          name TEXT NOT NULL, 
                          quantity INTEGER NOT NULL,
                          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)''')
        conn.commit()
        conn.close()

init_db()

def send_email(to_email, subject, body):
    """Envía un correo con las instrucciones de recuperación de contraseña."""
    if not EMAIL_USER or not EMAIL_PASSWORD:
        print("Error: Configuración de correo no encontrada.")
        return False

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_USER
    msg["To"] = to_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USER, to_email, msg.as_string())
        print("Correo enviado con éxito.")
        return True
    except Exception as e:
        print(f"Error al enviar correo: {e}")
        return False

@app.route("/register", methods=["GET", "POST"])
def register():
    """Muestra y procesa el registro de un nuevo usuario."""
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        if not username or not password:
            flash("Todos los campos son obligatorios.", "warning")
        elif len(password) < 6:
            flash("La contraseña debe tener al menos 6 caracteres.", "warning")
        else:
            hashed_password = generate_password_hash(password)
            conn = get_db_connection()
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
                    conn.commit()
                    flash("Usuario registrado con éxito. Inicia sesión.", "success")
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    flash("El usuario ya existe. Intenta con otro nombre.", "danger")
                finally:
                    conn.close()
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Muestra y procesa el inicio de sesión."""
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()

            if user and check_password_hash(user["password"], password):
                session["user_id"] = user["id"]
                flash("Inicio de sesión exitoso.", "success")
                return redirect(url_for("get_products"))
            else:
                flash("Credenciales incorrectas. Intenta nuevamente.", "danger")
    return render_template("login.html")

@app.route("/recover_password", methods=["GET", "POST"])
def recover_password():
    """Muestra y procesa la recuperación de la contraseña."""
    if request.method == "POST":
        username = request.form.get("username").strip()
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user:
                reset_token = str(randint(100000, 999999))  # Token aleatorio de 6 dígitos
                cursor.execute("UPDATE users SET reset_token = ? WHERE id = ?", (reset_token, user["id"]))
                conn.commit()
                send_email(username, "Recuperación de contraseña", f"Tu código de recuperación es: {reset_token}")
                flash("Se ha enviado un código de recuperación a tu correo.", "success")
                return redirect(url_for("login"))
            else:
                flash("El usuario no existe.", "danger")
            conn.close()
    return render_template("recover_password.html")

@app.route("/logout")
def logout():
    """Cierra la sesión del usuario."""
    session.pop("user_id", None)
    flash("Sesión cerrada con éxito.", "info")
    return redirect(url_for("login"))

@app.route("/products", methods=["GET"])
def get_products():
    """Muestra los productos del usuario logueado."""
    if "user_id" not in session:
        flash("Debes iniciar sesión para ver el inventario.", "warning")
        return redirect(url_for("login"))
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, quantity FROM products WHERE user_id = ?", (session["user_id"],))
        products = cursor.fetchall()
        conn.close()
        return render_template("inventory.html", products=products)

@app.route('/add_product', methods=['POST'])
def add_product():
    """Agrega un nuevo producto al inventario."""
    if "user_id" not in session:
        flash("Debes iniciar sesión para agregar productos.", "warning")
        return redirect(url_for("login"))

    name = request.form.get('name').strip()
    quantity = request.form.get('quantity').strip()

    if not name or not quantity or not quantity.isdigit():
        flash("Por favor, ingresa un nombre y una cantidad válida para el producto.", "warning")
        return redirect(url_for("get_products"))

    quantity = int(quantity)

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO products (user_id, name, quantity) VALUES (?, ?, ?)", 
                       (session["user_id"], name, quantity))
        conn.commit()
        conn.close()

        flash("Producto agregado exitosamente.", "success")
        return redirect(url_for('get_products'))
    else:
        flash("Error al conectar con la base de datos. Intenta de nuevo.", "danger")
        return redirect(url_for('get_products'))
    
@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    """Permite editar los productos existentes."""
    if "user_id" not in session:
        flash("Debes iniciar sesión para editar productos.", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products WHERE id = ? AND user_id = ?", (product_id, session["user_id"]))
        product = cursor.fetchone()
        conn.close()

        if not product:
            flash("Producto no encontrado o no tienes permiso para editarlo.", "danger")
            return redirect(url_for("get_products"))

        if request.method == "POST":
            name = request.form.get('name').strip()
            quantity = request.form.get('quantity').strip()

            if not name or not quantity or not quantity.isdigit():
                flash("Por favor, ingresa un nombre y una cantidad válida para el producto.", "warning")
            else:
                quantity = int(quantity)
                conn = get_db_connection()
                if conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE products SET name = ?, quantity = ? WHERE id = ?", (name, quantity, product_id))
                    conn.commit()
                    conn.close()

                    flash("Producto actualizado exitosamente.", "success")
                    return redirect(url_for('get_products'))
                else:
                    flash("Error al conectar con la base de datos. Intenta de nuevo.", "danger")

    return render_template('edit_product.html', product=product)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    """Elimina un producto del inventario.""" 
    if "user_id" not in session:
        flash("Debes iniciar sesión para eliminar productos.", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products WHERE id = ? AND user_id = ?", (product_id, session["user_id"]))
        product = cursor.fetchone()

        if product:
            cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
            conn.commit()
            flash("Producto eliminado correctamente.", "success")
        else:
            flash("Producto no encontrado o no tienes permiso para eliminarlo.", "danger")
        conn.close()

    return redirect(url_for('get_products'))

if __name__ == "__main__":
    app.run(debug=True)
