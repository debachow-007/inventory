# app.py

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import datetime
from sqlalchemy import or_

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Configuration ---
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
    password = db.Column(db.String(120), nullable=False) # Plain text password for dev
    role = db.Column(db.String(20), default='staff') # e.g., 'admin', 'staff'

    orders = db.relationship('Order', backref='user', lazy=True)
    transfers = db.relationship('Transfer', backref='user', lazy=True)
    tasks_assigned = db.relationship('Task', foreign_keys='Task.assigned_to_id', backref='assigned_user', lazy=True)
    tasks_created = db.relationship('Task', foreign_keys='Task.created_by_id', backref='created_by_user', lazy=True)

    def set_password(self, password):
        self.password = password

    def check_password(self, password):
        return self.password == password

    def __repr__(self):
        return f'<User {self.username}>'

class Good(db.Model):
    __tablename__ = 'goods'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    unit = db.Column(db.String(20), nullable=False)
    current_stock_quantity = db.Column(db.Float, default=0.0)
    reorder_level = db.Column(db.Float, default=0.0)

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
    expiry_date = db.Column(db.Date, nullable=True)

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

    orders = db.relationship('Order', backref='supplier', lazy=True)
    payments = db.relationship('Payment', backref='supplier', lazy=True)

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
    payment_method = db.Column(db.String(20), default='credit') # 'cash', 'credit'

    details = db.relationship('OrderDetail', backref='order', lazy=True, cascade="all, delete-orphan")
    payments = db.relationship('Payment', secondary='order_payment_association', backref='orders', lazy=True)

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
    supplier_id = db.Column(db.Integer, db.ForeignKey('suppliers.id'), nullable=False)
    payment_date = db.Column(db.Date, default=datetime.date.today)
    amount = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(50), nullable=True)
    notes = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Payment ID: {self.id}, Supplier: {self.supplier.name}, Amount: {self.amount}>'

order_payment_association = db.Table('order_payment_association',
    db.Column('order_id', db.Integer, db.ForeignKey('orders.id'), primary_key=True),
    db.Column('payment_id', db.Integer, db.ForeignKey('payments.id'), primary_key=True)
)

class Transfer(db.Model):
    __tablename__ = 'transfers'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    good_id = db.Column(db.Integer, db.ForeignKey('goods.id'), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    transfer_date = db.Column(db.DateTime, default=datetime.datetime.now)
    transfer_type = db.Column(db.String(20), nullable=False)
    notes = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Transfer {self.transfer_type} of {self.good.name} Qty: {self.quantity}>'

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), default='pending')
    priority = db.Column(db.String(20), default='medium')
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

# --- Common Routes (Accessible to all logged-in users, or public) ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin.dashboard'))
        else:
            return redirect(url_for('staff.dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('staff.dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if User.query.first() and not (current_user.is_authenticated and current_user.role == 'admin'):
        flash('Registration is currently disabled or requires admin.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'staff')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
        else:
            new_user = User(username=username, role=role)
            new_user.set_password(password)
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

# --- Blueprint for Admin Features ---
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.before_request
@login_required
def admin_bp_before_request():
    if current_user.role != 'admin':
        flash('You do not have administrative permission to access this page.', 'danger')
        return redirect(url_for('index'))

@admin_bp.route('/dashboard')
def dashboard():
    inventory_items = Good.query.order_by(Good.current_stock_quantity.asc()).limit(5).all()
    pending_orders = Order.query.filter_by(status='pending').order_by(Order.order_date.desc()).limit(5).all()
    upcoming_tasks = Task.query.filter(Task.status == 'pending', Task.due_date >= datetime.date.today()).order_by(Task.due_date.asc()).limit(5).all()
    expiry_threshold = datetime.date.today() + datetime.timedelta(days=30)
    expiring_batches = Batch.query.filter(
        Batch.expiry_date.isnot(None),
        Batch.expiry_date <= expiry_threshold,
        Batch.quantity > 0
    ).order_by(Batch.expiry_date.asc()).limit(5).all()
    return render_template('admin/dashboard.html',
                           inventory_items=inventory_items,
                           pending_orders=pending_orders,
                           upcoming_tasks=upcoming_tasks,
                           expiring_batches=expiring_batches,
                           now=datetime.datetime.now())

@admin_bp.route('/inventory')
def inventory():
    return render_template('admin/inventory.html', goods=[])

@admin_bp.route('/orders')
def orders():
    return render_template('admin/orders.html', orders=[])

@admin_bp.route('/tasks')
def tasks():
    return render_template('admin/tasks.html', tasks=[], users=User.query.all())

@admin_bp.route('/suppliers')
def suppliers():
    return render_template('admin/suppliers.html', suppliers=[])

@admin_bp.route('/users')
def users():
    return render_template('admin/users.html', users=[])

@admin_bp.route('/payments')
def payments():
    return render_template('admin/payments.html', payments=[], suppliers=Supplier.query.all())

@admin_bp.route('/transfers')
def transfers():
    return render_template('admin/transfers.html', transfers=[], goods=Good.query.all(), users=User.query.all())


# --- Blueprint for Staff/Non-Admin Features ---
staff_bp = Blueprint('staff', __name__, url_prefix='/staff')

@staff_bp.before_request
@login_required
def staff_bp_before_request():
    pass

@staff_bp.route('/dashboard')
def dashboard():
    inventory_items = Good.query.order_by(Good.current_stock_quantity.asc()).limit(5).all() # Also pass for staff dashboard
    pending_orders = Order.query.filter_by(status='pending').order_by(Order.order_date.desc()).limit(5).all()
    my_assigned_tasks = Task.query.filter(
        (Task.assigned_to_id == current_user.id) | (Task.created_by_id == current_user.id),
        Task.status != 'completed'
    ).order_by(Task.due_date.asc()).limit(5).all()
    
    return render_template('staff/dashboard.html',
                           inventory_items=inventory_items, # Pass this
                           pending_orders=pending_orders,
                           my_assigned_tasks=my_assigned_tasks,
                           now=datetime.datetime.now())

@staff_bp.route('/inventory')
def inventory():
    return render_template('staff/inventory.html', goods=[])

@staff_bp.route('/orders')
def orders():
    return render_template('staff/orders.html', orders=[])

@staff_bp.route('/tasks')
def tasks():
    return render_template('staff/tasks.html', tasks=[], users=User.query.all())

@staff_bp.route('/payments')
def payments():
    return render_template('staff/payments.html', payments=[], suppliers=Supplier.query.all())


# --- API Endpoints for CRUD Operations (Generic) ---
def create_crud_endpoints(bp, model, name, allow_non_admin=False):
    # Get all items
    @bp.route(f'/api/{name}', methods=['GET'], endpoint=f'get_all_{name}')
    def get_all():
        if not allow_non_admin and current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        search_query = request.args.get('search', '').strip()
        sort_by = request.args.get('sort_by', None)
        sort_order = request.args.get('sort_order', 'asc') # 'asc' or 'desc'

        items_query = model.query

        # Apply search filtering
        if search_query:
            search_filters = []
            if model == Good:
                search_filters.append(Good.name.ilike(f'%{search_query}%'))
                search_filters.append(Good.unit.ilike(f'%{search_query}%'))
            elif model == Order:
                search_filters.append(Order.status.ilike(f'%{search_query}%'))
                search_filters.append(Order.supplier.has(Supplier.name.ilike(f'%{search_query}%')))
                search_filters.append(Order.details.any(OrderDetail.good.has(Good.name.ilike(f'%{search_query}%'))))
            elif model == Supplier:
                search_filters.append(Supplier.name.ilike(f'%{search_query}%'))
                search_filters.append(Supplier.contact_person.ilike(f'%{search_query}%'))
                search_filters.append(Supplier.email.ilike(f'%{search_query}%'))
                search_filters.append(Supplier.phone.ilike(f'%{search_query}%'))
                search_filters.append(Supplier.address.ilike(f'%{search_query}%'))
            elif model == Task:
                search_filters.append(Task.title.ilike(f'%{search_query}%'))
                search_filters.append(Task.description.ilike(f'%{search_query}%'))
                search_filters.append(Task.status.ilike(f'%{search_query}%'))
                search_filters.append(Task.priority.ilike(f'%{search_query}%'))
                search_filters.append(Task.assigned_user.has(User.username.ilike(f'%{search_query}%')))
                search_filters.append(Task.created_by_user.has(User.username.ilike(f'%{search_query}%')))
            elif model == Payment:
                search_filters.append(Payment.payment_method.ilike(f'%{search_query}%'))
                search_filters.append(Payment.notes.ilike(f'%{search_query}%'))
                search_filters.append(Payment.supplier.has(Supplier.name.ilike(f'%{search_query}%')))
            elif model == User:
                search_filters.append(User.username.ilike(f'%{search_query}%'))
                search_filters.append(User.role.ilike(f'%{search_query}%'))
            elif model == Transfer:
                search_filters.append(Transfer.transfer_type.ilike(f'%{search_query}%'))
                search_filters.append(Transfer.notes.ilike(f'%{search_query}%'))
                search_filters.append(Transfer.good.has(Good.name.ilike(f'%{search_query}%')))
                search_filters.append(Transfer.user.has(User.username.ilike(f'%{search_query}%')))


            if search_filters:
                items_query = items_query.filter(or_(*search_filters))

        # Apply sorting
        if sort_by:
            if model == Order and sort_by == 'supplier_name':
                column = Supplier.name
                items_query = items_query.join(Supplier)
            elif model == Task and sort_by == 'assigned_to_username':
                column = User.username
                items_query = items_query.outerjoin(Task.assigned_user)
            elif model == Task and sort_by == 'created_by_username':
                column = User.username
                items_query = items_query.join(Task.created_by_user)
            elif model == Payment and sort_by == 'supplier_name':
                column = Supplier.name
                items_query = items_query.join(Supplier)
            elif model == Transfer and sort_by == 'good_name':
                column = Good.name
                items_query = items_query.join(Good)
            elif model == Transfer and sort_by == 'user_username':
                column = User.username
                items_query = items_query.join(User)
            else:
                column = getattr(model, sort_by, None)

            if column:
                if sort_order == 'desc':
                    items_query = items_query.order_by(column.desc())
                else:
                    items_query = items_query.order_by(column.asc())

        items = items_query.all()
        return jsonify([item.to_dict() if hasattr(item, 'to_dict') else item.__dict__ for item in items])

    # Get single item
    @bp.route(f'/api/{name}/<int:item_id>', methods=['GET'], endpoint=f'get_single_{name}')
    def get_single(item_id):
        if not allow_non_admin and current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        item = model.query.get_or_404(item_id)
        return jsonify(item.to_dict() if hasattr(item, 'to_dict') else item.__dict__)

    # Add new item
    @bp.route(f'/api/{name}', methods=['POST'], endpoint=f'add_item_{name}')
    def add_item():
        if not allow_non_admin and current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.json
        try:
            if model == User:
                if data.get('role') == 'admin' and current_user.role != 'admin':
                     return jsonify({'error': 'Only admins can create admin users.'}), 403
                
                new_item = model(username=data['username'], role=data.get('role', 'staff'))
                new_item.set_password(data['password'])
            elif model == Order:
                new_item = model(user_id=current_user.id, **{k: v for k, v in data.items() if k != 'details'})
                db.session.add(new_item)
                db.session.flush()

                for detail_data in data.get('details', []):
                    order_detail = OrderDetail(order_id=new_item.id, **detail_data)
                    db.session.add(order_detail)
            elif model == Payment:
                new_item = model(supplier_id=data['supplier_id'], amount=data['amount'],
                                payment_method=data.get('payment_method'), notes=data.get('notes'))
                db.session.add(new_item)
                db.session.flush()
                
                for order_id in data.get('order_ids', []):
                    order = Order.query.get(order_id)
                    if order:
                        new_item.orders.append(order)
            elif model == Transfer:
                good = Good.query.get(data['good_id'])
                if not good:
                    raise ValueError(f"Good with ID {data['good_id']} not found.")

                quantity = float(data['quantity'])
                transfer_type = data['transfer_type']

                if transfer_type in ['out', 'waste', 'consumption'] and good.current_stock_quantity < quantity:
                    raise ValueError(f"Insufficient stock for {good.name}. Available: {good.current_stock_quantity} {good.unit}, Attempted: {quantity} {good.unit}")

                new_item = model(
                    user_id=current_user.id,
                    good_id=data['good_id'],
                    quantity=quantity,
                    transfer_type=transfer_type,
                    notes=data.get('notes')
                )
                db.session.add(new_item)

                if transfer_type == 'in':
                    good.current_stock_quantity += quantity
                elif transfer_type in ['out', 'waste', 'consumption']:
                    good.current_stock_quantity -= quantity
            else:
                new_item = model(**data)
            
            if model not in [Order, Payment, Transfer]:
                db.session.add(new_item)
            
            db.session.commit()
            return jsonify({'message': f'{name.capitalize()} added successfully', 'id': new_item.id}), 201
        except Exception as e:
            db.session.rollback()
            print(f"Error adding {name}: {e}")
            return jsonify({'error': str(e)}), 400

    # Update item
    @bp.route(f'/api/{name}/<int:item_id>', methods=['PUT'], endpoint=f'update_item_{name}')
    def update_item(item_id):
        if not allow_non_admin and current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403

        item = model.query.get_or_404(item_id)
        data = request.json
        try:
            if model == Transfer:
                flash("Directly updating transfers might not adjust stock automatically. Consider deleting and re-creating for accurate stock changes.", "warning")
                updatable_fields = ['notes', 'transfer_date']
                for key, value in data.items():
                    if key in updatable_fields and hasattr(item, key) and key != 'id':
                        if isinstance(getattr(model, key).type, db.DateTime) and isinstance(value, str):
                            setattr(item, key, datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S'))
                        else:
                            setattr(item, key, value)
            else:
                for key, value in data.items():
                    if hasattr(item, key) and key != 'id':
                        if key == 'password' and model == User:
                            item.set_password(value)
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
            print(f"Error updating {name}: {e}")
            return jsonify({'error': str(e)}), 400

    # Delete item
    @bp.route(f'/api/{name}/<int:item_id>', methods=['DELETE'], endpoint=f'delete_item_{name}')
    def delete_item(item_id):
        if not allow_non_admin and current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        item = model.query.get_or_404(item_id)
        try:
            if model == Transfer:
                good = Good.query.get(item.good_id)
                if good:
                    if item.transfer_type == 'in':
                        good.current_stock_quantity -= item.quantity
                    elif item.transfer_type in ['out', 'waste', 'consumption']:
                        good.current_stock_quantity += item.quantity
                    db.session.add(good)
                else:
                    print(f"Warning: Good with ID {item.good_id} not found for transfer {item.id} during deletion.")

            db.session.delete(item)
            db.session.commit()
            return jsonify({'message': f'{name.capitalize()} deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error deleting {name}: {e}")
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
    total_credit_orders_amount = sum(
        order.total_amount for order in self.orders
        if order.status == 'completed' and order.payment_method == 'credit'
    )
    total_payments_amount = sum(payment.amount for payment in self.payments)
    
    outstanding_amount = total_credit_orders_amount - total_payments_amount
    outstanding_amount = max(0, outstanding_amount) 

    return {
        'id': self.id,
        'name': self.name,
        'contact_person': self.contact_person,
        'phone': self.phone,
        'email': self.email,
        'address': self.address,
        'outstanding_amount': outstanding_amount
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
        'payment_method': self.payment_method,
        'details': [detail.to_dict() for detail in self.details] if self.details else []
    }
Order.to_dict = order_to_dict

def order_detail_to_dict(self):
    return {
        'id': self.id,
        'order_id': self.order_id,
        'good_id': self.good_id,
        'good_name': self.good.name if self.good else None,
        'good_unit': self.good.unit if self.good else None,
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
        'supplier_id': self.supplier_id,
        'supplier_name': self.supplier.name if self.supplier else None,
        'payment_date': self.payment_date.isoformat() if self.payment_date else None,
        'amount': self.amount,
        'payment_method': self.payment_method,
        'notes': self.notes,
        'associated_orders': [order.id for order in self.orders]
    }
Payment.to_dict = payment_to_dict

def transfer_to_dict(self):
    return {
        'id': self.id,
        'user_id': self.user_id,
        'user_username': self.user.username if self.user else None,
        'good_id': self.good_id,
        'good_name': self.good.name if self.good else None,
        'good_unit': self.good.unit if self.good else None,
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


# Register CRUD endpoints for Admin Blueprint (full access)
create_crud_endpoints(admin_bp, User, 'users', allow_non_admin=False)
create_crud_endpoints(admin_bp, Good, 'goods', allow_non_admin=False)
create_crud_endpoints(admin_bp, Order, 'orders', allow_non_admin=False)
create_crud_endpoints(admin_bp, Batch, 'batches', allow_non_admin=False)
create_crud_endpoints(admin_bp, Supplier, 'suppliers', allow_non_admin=False)
create_crud_endpoints(admin_bp, Transfer, 'transfers', allow_non_admin=False)
create_crud_endpoints(admin_bp, Task, 'tasks', allow_non_admin=False)

# Register CRUD endpoints for Staff Blueprint (limited access)
create_crud_endpoints(staff_bp, Order, 'orders', allow_non_admin=True)
create_crud_endpoints(staff_bp, OrderDetail, 'order_details', allow_non_admin=True)
create_crud_endpoints(staff_bp, Task, 'tasks', allow_non_admin=True)
create_crud_endpoints(staff_bp, Payment, 'payments', allow_non_admin=True)


# Staff can GET suppliers and goods, but not add/edit/delete them
@staff_bp.route('/api/goods', methods=['GET'], endpoint='get_all_goods_staff')
@login_required
def get_all_goods_staff():
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', None)
    sort_order = request.args.get('sort_order', 'asc')

    items_query = Good.query

    if search_query:
        items_query = items_query.filter(or_(
            Good.name.ilike(f'%{search_query}%'),
            Good.unit.ilike(f'%{search_query}%')
        ))
    
    if sort_by:
        column = getattr(Good, sort_by, None)
        if column:
            if sort_order == 'desc':
                items_query = items_query.order_by(column.desc())
            else:
                items_query = items_query.order_by(column.asc())

    goods = items_query.all()
    return jsonify([good.to_dict() for good in goods])

@staff_bp.route('/api/suppliers', methods=['GET'], endpoint='get_all_suppliers_staff')
@login_required
def get_all_suppliers_staff():
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', None)
    sort_order = request.args.get('sort_order', 'asc')

    items_query = Supplier.query

    if search_query:
        items_query = items_query.filter(or_(
            Supplier.name.ilike(f'%{search_query}%'),
            Supplier.contact_person.ilike(f'%{search_query}%'),
            Supplier.email.ilike(f'%{search_query}%'),
            Supplier.phone.ilike(f'%{search_query}%'),
            Supplier.address.ilike(f'%{search_query}%')
        ))
    
    if sort_by:
        column = getattr(Supplier, sort_by, None)
        if column:
            if sort_order == 'desc':
                items_query = items_query.order_by(column.desc())
            else:
                items_query = items_query.order_by(column.asc())

    suppliers = items_query.all()
    return jsonify([supplier.to_dict() for supplier in suppliers])


# --- Specific API Endpoints for Actions ---

@admin_bp.route('/api/orders/<int:order_id>/complete', methods=['POST'])
@staff_bp.route('/api/orders/<int:order_id>/complete', methods=['POST'])
@login_required
def complete_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.status == 'pending':
        order.status = 'completed'
        data = request.json
        batches_data = data.get('batches', [])
        payment_method = data.get('payment_method', 'credit')

        order.payment_method = payment_method

        try:
            for batch_info in batches_data:
                good_id = batch_info.get('good_id')
                batch_number = batch_info.get('batch_number')
                quantity_received = float(batch_info.get('quantity_received'))
                expiry_date_str = batch_info.get('expiry_date')

                if not all([good_id, batch_number, quantity_received is not None]):
                    raise ValueError("Missing batch details for completion.")

                if quantity_received <= 0:
                    continue

                expiry_date = datetime.datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None

                new_batch = Batch(
                    good_id=good_id,
                    batch_number=batch_number,
                    quantity=quantity_received,
                    purchase_date=datetime.date.today(),
                    expiry_date=expiry_date
                )
                db.session.add(new_batch)

                good = Good.query.get(good_id)
                if good:
                    good.current_stock_quantity += quantity_received
                else:
                    raise ValueError(f"Good with ID {good_id} not found.")

            if payment_method == 'cash' and order.total_amount > 0:
                new_payment = Payment(
                    supplier_id=order.supplier_id,
                    amount=order.total_amount,
                    payment_method='cash',
                    notes=f"Cash payment for Order #{order.id}"
                )
                db.session.add(new_payment)
                db.session.flush()
                new_payment.orders.append(order)

            db.session.commit()
            return jsonify({'message': 'Order completed and inventory updated successfully'}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error completing order: {e}")
            return jsonify({'error': f'Failed to complete order or update inventory: {str(e)}'}), 400
    else:
        return jsonify({'message': 'Order is not in pending status.'}), 400

@admin_bp.route('/api/tasks/<int:task_id>/complete', methods=['POST'])
@staff_bp.route('/api/tasks/<int:task_id>/complete', methods=['POST'])
@login_required
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

@admin_bp.route('/api/suppliers/<int:supplier_id>/outstanding_orders', methods=['GET'])
@staff_bp.route('/api/suppliers/<int:supplier_id>/outstanding_orders', methods=['GET'])
@login_required
def get_outstanding_orders(supplier_id):
    supplier_orders = Order.query.filter_by(supplier_id=supplier_id, status='completed', payment_method='credit').all()
    
    outstanding_orders_list = []
    for order in supplier_orders:
        paid_amount_for_order = sum(p.amount for p in order.payments)
        
        if order.total_amount > paid_amount_for_order:
            outstanding_orders_list.append({
                'id': order.id,
                'order_date': order.order_date.isoformat(),
                'total_amount': order.total_amount,
                'amount_paid': paid_amount_for_order,
                'outstanding_amount': order.total_amount - paid_amount_for_order
            })
    
    return jsonify(outstanding_orders_list)


# --- Register Blueprints ---
app.register_blueprint(admin_bp)
app.register_blueprint(staff_bp)

# --- Database Creation (Run this once to create your tables) ---
@app.cli.command('create-db')
def create_db():
    """Creates database tables."""
    with app.app_context():
        db.create_all()
        print("Database tables created.")

        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', role='admin')
            admin_user.set_password('adminpass')
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user 'admin' created with password 'adminpass'.")
        
        if not User.query.filter_by(username='staff').first():
            staff_user = User(username='staff', role='staff')
            staff_user.set_password('staffpass')
            db.session.add(staff_user)
            db.session.commit()
            print("Default staff user 'staff' created with password 'staffpass'.")

if __name__ == '__main__':
    app.run(debug=True)
