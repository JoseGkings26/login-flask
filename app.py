from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps 




app = Flask(__name__)
# ¡IMPORTANTE! Cambia esto por una cadena de texto larga y aleatoria y mantenla en secreto.
# Se usa para proteger las sesiones de usuario.
app.secret_key = 'tu_clave_secreta_super_segura_y_larga_aqui_12345' 

# Nombre del archivo de la base de datos SQLite
DATABASE = 'users.db'

# --- CREDENCIALES DEL ADMINISTRADOR ---
# ¡IMPORTANTE! Cambia estas credenciales por algo seguro.
ADMIN_USERNAME = "ADMIN2025"
ADMIN_PASSWORD = "ADMIN2025"

# --- Funciones para la Base de Datos ---

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row 
    return conn

def init_db():
    with app.app_context(): 
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        conn.commit()
        
        cursor.execute("SELECT * FROM users WHERE username = ?", (ADMIN_USERNAME,))
        if not cursor.fetchone():
            print(f"INFO: No se encontró el usuario administrador '{ADMIN_USERNAME}'. Creándolo ahora.")
            hashed_admin_password = generate_password_hash(ADMIN_PASSWORD)
            try:
                cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                               (ADMIN_USERNAME, hashed_admin_password))
                conn.commit()
                print(f"INFO: Usuario administrador '{ADMIN_USERNAME}' creado exitosamente con la contraseña predefinida.")
            except sqlite3.IntegrityError:
                print(f"INFO: El usuario administrador '{ADMIN_USERNAME}' ya existe (duplicado).")
        
        conn.close()

# --- Decoradores para Proteger Rutas ---

def login_required(f):
    @wraps(f) 
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session.get('logged_in'):
            flash('Debes iniciar sesión para acceder a esta página.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or session.get('username') != ADMIN_USERNAME:
            flash('No tienes permisos de administrador para acceder a esta página.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Rutas de la Aplicación ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if not username or not password:
            flash('Por favor, ingresa tu usuario y contraseña.', 'danger')
            return redirect(url_for('index'))

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['logged_in'] = True
            session['username'] = user['username']
            flash('Inicio de sesión exitoso!', 'success')
            
            if user['username'] == ADMIN_USERNAME:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('bienvenido'))
        else:
            flash('Usuario o contraseña incorrectos. Inténtalo de nuevo.', 'danger')
            return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('Has cerrado sesión exitosamente.', 'info')
    # Después de cerrar sesión, redirige a la página de inicio (index)
    return redirect(url_for('index')) # Se redirige a la página de inicio por defecto.

# NUEVA RUTA PARA TU PÁGINA PERSONALIZADA (DESPUÉS DEL LOGIN)
@app.route('/acceso_mi_pagina_secreta') 
@login_required 
def mostrar_mi_pagina_secreta():
    return render_template('http://localhost:3000/') 

@app.route('/bienvenido')
@login_required 
def bienvenido():
    return render_template('bienvenido.html')

@app.route('/admin_panel', methods=['GET', 'POST'])
@admin_required 
def admin_panel():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username FROM users').fetchall()
    conn.close()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'create_user':
            username = request.form['username'].strip()
            password = request.form['password'].strip()
            
            if not username or not password:
                flash('Por favor, completa ambos campos para crear un usuario.', 'danger')
                return redirect(url_for('admin_panel')) 

            hashed_password = generate_password_hash(password)

            conn = get_db_connection()
            try:
                conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                             (username, hashed_password))
                conn.commit()
                flash(f"Usuario '{username}' creado exitosamente.", 'success')
            except sqlite3.IntegrityError:
                flash(f"El nombre de usuario '{username}' ya existe. Por favor, elige otro.", 'danger')
            except Exception as e:
                flash(f"Error al crear usuario: {e}", 'danger')
            finally:
                conn.close()
            return redirect(url_for('admin_panel')) 

        elif action == 'delete_user':
            user_id = request.form.get('user_id')
            if user_id:
                try:
                    user_id = int(user_id) 
                    conn = get_db_connection()
                    
                    user_to_delete = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
                    if user_to_delete and user_to_delete['username'] == ADMIN_USERNAME:
                        flash('No puedes eliminar la cuenta de administrador principal.', 'danger')
                    else:
                        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
                        conn.commit()
                        flash(f'Usuario con ID {user_id} eliminado exitosamente.', 'success')
                except ValueError:
                    flash('ID de usuario inválido para eliminar.', 'danger')
                except Exception as e:
                    flash(f'Error al eliminar usuario: {e}', 'danger')
                finally:
                    conn.close()
            return redirect(url_for('admin_panel')) 
    
    return render_template('admin_panel.html', users=users)

if __name__ == '__main__':
    init_db() 
    app.run(debug=True)