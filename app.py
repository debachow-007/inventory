# app.py

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
# Removed: from werkzeug.security import generate_password_hash, check_password_hash
import datetime

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Configuration ---
# Replace with your actual database URI
# Example for MySQL: 'mysql+pymysql://user:password@host/db_name'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/inventory'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_super_secret_key_here_please_change' # Change this!

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # The view to redirect to for login

# --- Database Models ---

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Changed from password_hash to password
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='staff') # e.g., 'admin', 'staff'

    # Relationships
    orders = db.relationship('Order', backref='user', lazy=True)
    transfers = db.relationship('Transfer', backref='user', lazy=True)
    tasks_assigned = db.relationship('Task', foreign_keys='Task.assigned_to_id', backref='assigned_user', lazy=True)
    tasks_created = db.relationship('Task', foreign_keys='Task.created_by_id', backref='created_by_user', lazy=True)


    def set_password(self, password):
        # Storing password in plain text - NOT SECURE FOR PRODUCTION
        self.password = password

    def check_password(self, password):
        # Comparing plain text password - NOT SECURE FOR PRODUCTION
        return self.password == password

    def __repr__(self):
        return f'<User {self.username}>'

class Good(db.Model):
    __tablename__ = 'goods'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    unit = db.Column(db.String(20), nullable=False) # e.g., 'kg', 'liter', 'piece'
    current_stock_quantity = db.Column(db.Float, default=0.0)
    reorder_level = db.Column(db.Float, default=0.0) # When to reorder this item

    # Relationships
    batches = db.relationship('Batch', backref='good', lazy=True, cascade="all, delete-orphan")
    order_details = db.relationship('OrderDetail', backref='good', lazy=True)
    transfers = db.relationship('Transfer', backref='good', lazy=True)

    def __repr__(self):
        return f'<Good {self.name}>'

class Batch(db.Model):
    __tablename__ = 'batches'
    id = db.Column(db.Integer, primary_key=True)
    good_id = db.Column(db.Integer, db.ForeignKey('goods.id'), nullable=False)
    batch_number = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    purchase_date = db.Column(db.Date, default=datetime.date.today)
    expiry_date = db.Column(db.Date, nullable=True) # Optional expiry date

    def __repr__(self):
        return f'<Batch {self.batch_number} for {self.good.name}>'

class Supplier(db.Model):
    __tablename__ = 'suppliers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    contact_person = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(100), nullable=True)
    address = db.Column(db.String(200), nullable=True)

    # Relationships
    orders = db.relationship('Order', backref='supplier', lazy=True)

    def __repr__(self):
        return f'<Supplier {self.name}>'

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    supplier_id = db.Column(db.Integer, db.ForeignKey('suppliers.id'), nullable=True)
    order_date = db.Column(db.Date, default=datetime.date.today)
    expected_delivery_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), default='pending') # e.g., 'pending', 'completed', 'cancelled'
    total_amount = db.Column(db.Float, default=0.0)

    # Relationships
    details = db.relationship('OrderDetail', backref='order', lazy=True, cascade="all, delete-orphan")
    payments = db.relationship('Payment', backref='order', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Order {self.id} Status: {self.status}>'

class OrderDetail(db.Model):
    __tablename__ = 'order_details'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    good_id = db.Column(db.Integer, db.ForeignKey('goods.id'), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    price_per_unit = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f'<OrderDetail Order: {self.order_id}, Good: {self.good.name}, Qty: {self.quantity}>'

class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    payment_date = db.Column(db.Date, default=datetime.date.today)
    amount = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(50), nullable=True) # e.g., 'cash', 'card', 'bank transfer'

    def __repr__(self):
        return f'<Payment Order: {self.order_id}, Amount: {self.amount}>'

class Transfer(db.Model):
    __tablename__ = 'transfers'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) # User who initiated the transfer
    good_id = db.Column(db.Integer, db.ForeignKey('goods.id'), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    transfer_date = db.Column(db.DateTime, default=datetime.datetime.now)
    transfer_type = db.Column(db.String(20), nullable=False) # e.g., 'in', 'out', 'waste', 'consumption'
    notes = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Transfer {self.transfer_type} of {self.good.name} Qty: {self.quantity}>'

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), default='pending') # e.g., 'pending', 'completed', 'overdue'
    priority = db.Column(db.String(20), default='medium') # e.g., 'low', 'medium', 'high'
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    completed_at = db.Column(db.DateTime, nullable=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f'<Task {self.title} Status: {self.status}>'

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('login')) # Redirect to login page initially

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard')) # Redirect to dashboard if already logged in

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'admin') # Default to admin for initial setup

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
        else:
            new_user = User(username=username, role=role)
            new_user.set_password(password) # Will now store plain text password
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Admin Blueprint ---
# This helps organize admin-related routes and protect them
from flask import Blueprint

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.before_request
@login_required
def admin_bp_before_request():
    # Ensure only 'admin' role can access admin routes
    # You might want more sophisticated role management here
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index')) # Or a different error page

@admin_bp.route('/dashboard')
def dashboard():
    # Placeholder for dashboard data
    # TODO: Fetch actual data for stock overview, pending orders, expiring stocks
    inventory_items = Good.query.order_by(Good.current_stock_quantity.asc()).limit(5).all() # Low stock items
    pending_orders = Order.query.filter_by(status='pending').order_by(Order.order_date.desc()).limit(5).all()
    upcoming_tasks = Task.query.filter(Task.status == 'pending', Task.due_date >= datetime.date.today()).order_by(Task.due_date.asc()).limit(5).all()

    # Expiring stocks (e.g., within next 30 days)
    expiry_threshold = datetime.date.today() + datetime.timedelta(days=30)
    expiring_batches = Batch.query.filter(
        Batch.expiry_date.isnot(None),
        Batch.expiry_date <= expiry_threshold,
        Batch.quantity > 0 # Only show if there's quantity
    ).order_by(Batch.expiry_date.asc()).limit(5).all()


    return render_template('admin/dashboard.html',
                           inventory_items=inventory_items,
                           pending_orders=pending_orders,
                           upcoming_tasks=upcoming_tasks,
                           expiring_batches=expiring_batches)

@admin_bp.route('/inventory')
def inventory():
    goods = Good.query.all()
    return render_template('admin/inventory.html', goods=goods)

@admin_bp.route('/orders')
def orders():
    all_orders = Order.query.order_by(Order.order_date.desc()).all()
    return render_template('admin/orders.html', orders=all_orders)

@admin_bp.route('/tasks')
def tasks():
    all_tasks = Task.query.order_by(Task.due_date.asc()).all()
    return render_template('admin/tasks.html', tasks=all_tasks, users=User.query.all())

@admin_bp.route('/suppliers')
def suppliers():
    all_suppliers = Supplier.query.all()
    return render_template('admin/suppliers.html', suppliers=all_suppliers)

@admin_bp.route('/users')
def users():
    all_users = User.query.all()
    return render_template('admin/users.html', users=all_users)

# --- API Endpoints for CRUD Operations ---

# Generic API endpoint helper function
def create_crud_endpoints(bp, model, name):
    # Get all items
    @bp.route(f'/api/{name}', methods=['GET'], endpoint=f'get_all_{name}') # Unique endpoint name
    def get_all():
        items = model.query.all()
        return jsonify([item.to_dict() for item in items])


    # Get single item
    @bp.route(f'/api/{name}/<int:item_id>', methods=['GET'], endpoint=f'get_single_{name}') # Unique endpoint name
    def get_single(item_id):
        item = model.query.get_or_404(item_id)
        return jsonify(item.to_dict() if hasattr(item, 'to_dict') else item.__dict__)

    # Add new item
    @bp.route(f'/api/{name}', methods=['POST'], endpoint=f'add_item_{name}') # Unique endpoint name
    def add_item():
        data = request.json
        try:
            # Handle password for User model (plain text)
            if model == User and 'password' in data:
                new_item = model(username=data['username'], role=data.get('role', 'staff'))
                new_item.set_password(data['password']) # Store plain text password
                db.session.add(new_item)
            else:
                new_item = model(**data)
                db.session.add(new_item)
            db.session.commit()
            return jsonify({'message': f'{name.capitalize()} added successfully', 'id': new_item.id}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 400

    # Update item
    @bp.route(f'/api/{name}/<int:item_id>', methods=['PUT'], endpoint=f'update_item_{name}') # Unique endpoint name
    def update_item(item_id):
        item = model.query.get_or_404(item_id)
        data = request.json
        try:
            for key, value in data.items():
                if hasattr(item, key):
                    if key == 'password' and model == User:
                        item.set_password(value) # Set plain text password
                    # Special handling for date fields if needed
                    elif isinstance(getattr(model, key).type, db.Date) and isinstance(value, str):
                        setattr(item, key, datetime.datetime.strptime(value, '%Y-%m-%d').date())
                    elif isinstance(getattr(model, key).type, db.DateTime) and isinstance(value, str):
                        setattr(item, key, datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S'))
                    else:
                        setattr(item, key, value)
            db.session.commit()
            return jsonify({'message': f'{name.capitalize()} updated successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 400

    # Delete item
    @bp.route(f'/api/{name}/<int:item_id>', methods=['DELETE'], endpoint=f'delete_item_{name}') # Unique endpoint name
    def delete_item(item_id):
        item = model.query.get_or_404(item_id)
        try:
            db.session.delete(item)
            db.session.commit()
            return jsonify({'message': f'{name.capitalize()} deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 400

# Add to_dict methods for models to easily jsonify them
def good_to_dict(self):
    return {
        'id': self.id,
        'name': self.name,
        'unit': self.unit,
        'current_stock_quantity': self.current_stock_quantity,
        'reorder_level': self.reorder_level
    }
Good.to_dict = good_to_dict

def user_to_dict(self):
    return {
        'id': self.id,
        'username': self.username,
        'role': self.role
    }
User.to_dict = user_to_dict

def supplier_to_dict(self):
    return {
        'id': self.id,
        'name': self.name,
        'contact_person': self.contact_person,
        'phone': self.phone,
        'email': self.email,
        'address': self.address
    }
Supplier.to_dict = supplier_to_dict

def order_to_dict(self):
    return {
        'id': self.id,
        'user_id': self.user_id,
        'user_username': self.user.username if self.user else None,
        'supplier_id': self.supplier_id,
        'supplier_name': self.supplier.name if self.supplier else None,
        'order_date': self.order_date.isoformat() if self.order_date else None,
        'expected_delivery_date': self.expected_delivery_date.isoformat() if self.expected_delivery_date else None,
        'status': self.status,
        'total_amount': self.total_amount,
        'details': [detail.to_dict() for detail in self.details] if self.details else []
    }
Order.to_dict = order_to_dict

def order_detail_to_dict(self):
    return {
        'id': self.id,
        'order_id': self.order_id,
        'good_id': self.good_id,
        'good_name': self.good.name if self.good else None,
        'quantity': self.quantity,
        'price_per_unit': self.price_per_unit,
        'total_price': self.total_price
    }
OrderDetail.to_dict = order_detail_to_dict

def batch_to_dict(self):
    return {
        'id': self.id,
        'good_id': self.good_id,
        'good_name': self.good.name if self.good else None,
        'batch_number': self.batch_number,
        'quantity': self.quantity,
        'purchase_date': self.purchase_date.isoformat() if self.purchase_date else None,
        'expiry_date': self.expiry_date.isoformat() if self.expiry_date else None
    }
Batch.to_dict = batch_to_dict

def payment_to_dict(self):
    return {
        'id': self.id,
        'order_id': self.order_id,
        'payment_date': self.payment_date.isoformat() if self.payment_date else None,
        'amount': self.amount,
        'payment_method': self.payment_method
    }
Payment.to_dict = payment_to_dict

def transfer_to_dict(self):
    return {
        'id': self.id,
        'user_id': self.user_id,
        'user_username': self.user.username if self.user else None,
        'good_id': self.good_id,
        'good_name': self.good.name if self.good else None,
        'quantity': self.quantity,
        'transfer_date': self.transfer_date.isoformat() if self.transfer_date else None,
        'transfer_type': self.transfer_type,
        'notes': self.notes
    }
Transfer.to_dict = transfer_to_dict

def task_to_dict(self):
    return {
        'id': self.id,
        'title': self.title,
        'description': self.description,
        'due_date': self.due_date.isoformat() if self.due_date else None,
        'status': self.status,
        'priority': self.priority,
        'created_at': self.created_at.isoformat() if self.created_at else None,
        'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        'assigned_to_id': self.assigned_to_id,
        'assigned_to_username': self.assigned_user.username if self.assigned_user else None,
        'created_by_id': self.created_by_id,
        'created_by_username': self.created_by_user.username if self.created_by_user else None
    }
Task.to_dict = task_to_dict


# Register CRUD endpoints for each model
create_crud_endpoints(admin_bp, User, 'users')
create_crud_endpoints(admin_bp, Good, 'goods')
create_crud_endpoints(admin_bp, Batch, 'batches')
create_crud_endpoints(admin_bp, Supplier, 'suppliers')
create_crud_endpoints(admin_bp, Order, 'orders')
create_crud_endpoints(admin_bp, OrderDetail, 'order_details')
create_crud_endpoints(admin_bp, Payment, 'payments')
create_crud_endpoints(admin_bp, Transfer, 'transfers')
create_crud_endpoints(admin_bp, Task, 'tasks')

# --- Specific API Endpoints for Actions ---

@admin_bp.route('/api/orders/<int:order_id>/complete', methods=['POST'])
def complete_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.status == 'pending':
        order.status = 'completed'
        # Data for batches to be added
        data = request.json
        batches_data = data.get('batches', [])

        try:
            for batch_info in batches_data:
                good_id = batch_info.get('good_id')
                batch_number = batch_info.get('batch_number')
                quantity = batch_info.get('quantity')
                expiry_date_str = batch_info.get('expiry_date')

                if not all([good_id, batch_number, quantity]):
                    raise ValueError("Missing batch details for completion.")

                expiry_date = datetime.datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None

                # Add new batch
                new_batch = Batch(
                    good_id=good_id,
                    batch_number=batch_number,
                    quantity=quantity,
                    expiry_date=expiry_date
                )
                db.session.add(new_batch)

                # Update good's current stock
                good = Good.query.get(good_id)
                if good:
                    good.current_stock_quantity += quantity
                else:
                    raise ValueError(f"Good with ID {good_id} not found.")

            db.session.commit()
            return jsonify({'message': 'Order completed and inventory updated successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to complete order or update inventory: {str(e)}'}), 400
    else:
        return jsonify({'message': 'Order is not in pending status.'}), 400

@admin_bp.route('/api/tasks/<int:task_id>/complete', methods=['POST'])
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.status != 'completed':
        task.status = 'completed'
        task.completed_at = datetime.datetime.now()
        try:
            db.session.commit()
            return jsonify({'message': 'Task marked as completed'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 400
    else:
        return jsonify({'message': 'Task is already completed'}), 400

# --- Register Admin Blueprint ---
app.register_blueprint(admin_bp)

# --- Database Creation (Run this once to create your tables) ---
@app.cli.command('create-db')
def create_db():
    """Creates database tables."""
    with app.app_context():
        db.create_all()
        print("Database tables created.")

        # Optional: Add a default admin user if one doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', role='admin')
            admin_user.set_password('adminpass') # Will now store plain text password
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user 'admin' created with password 'adminpass'.")

# --- Main Run Block ---
if __name__ == '__main__':
    # To run:
    # 1. Ensure MySQL is running and you have created a database named 'restaurant_inventory'.
    # 2. Update SQLALCHEMY_DATABASE_URI in app.config with your MySQL credentials.
    # 3. Open your terminal in the project directory.
    # 4. Set FLASK_APP=app.py (Windows: set FLASK_APP=app.py, Linux/macOS: export FLASK_APP=app.py)
    # 5. Run 'flask create-db' to create tables and default admin user.
    # 6. Run 'flask run' to start the development server.
    app.run(debug=True) # debug=True is for development, set to False in production
