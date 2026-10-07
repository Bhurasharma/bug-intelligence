"""
Utility helpers for the Bug Intelligence Platform.
"""

import re
from typing import List, Tuple


# ── Severity color mapping ───────────────────────────────────────────
SEVERITY_COLORS = {
    "Critical": "#ff1744",
    "High": "#ff5722",
    "Medium": "#ff9800",
    "Low": "#ffc107",
    "Info": "#00bcd4",
}

SEVERITY_EMOJIS = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
    "Info": "ℹ️",
}

CATEGORY_ICONS = {
    "Bug": "🐛",
    "Code Smell": "👃",
    "Security": "🔒",
    "Performance": "⚡",
    "Maintainability": "🔧",
    "Reliability": "🛡️",
}


def risk_color(score: float) -> str:
    """Get color for risk score."""
    if score >= 8:
        return "#ff1744"
    elif score >= 6:
        return "#ff5722"
    elif score >= 4:
        return "#ff9800"
    elif score >= 2:
        return "#ffc107"
    else:
        return "#4caf50"


def risk_label(score: float) -> str:
    """Get label for risk score."""
    if score >= 8:
        return "Critical Risk"
    elif score >= 6:
        return "High Risk"
    elif score >= 4:
        return "Medium Risk"
    elif score >= 2:
        return "Low Risk"
    else:
        return "Healthy"


def complexity_color(rating: str) -> str:
    """Get color for complexity rating."""
    colors = {'A': '#4caf50', 'B': '#8bc34a', 'C': '#ff9800', 'D': '#ff5722', 'F': '#ff1744'}
    return colors.get(rating, '#9e9e9e')


SAMPLE_BUGGY_CODE = '''"""
Sample E-Commerce Order Processing System
This file intentionally contains various bugs and code smells for demonstration.
"""

import os
from os import *
import imp

# Hardcoded credentials (Security Issue)
DATABASE_PASSWORD = "super_secret_123"
API_KEY = "sk-abc123def456ghi789jkl012mno345"

# Global mutable state
order_cache = {}
total_revenue = 0


def process_order(order_id, items=[], discount=0):
    """Process a customer order."""
    global total_revenue
    
    # Type comparison instead of isinstance
    if type(items) == list:
        for item in items:
            items.append(item)  # Modifying list while iterating
    
    total = 0
    for item in items:
        price = item.get('price', 0)
        quantity = item.get('quantity', 1)
        total += price * quantity
    
    # Apply discount
    if discount:
        total = total - (total * discount / 100)
    
    total_revenue = total_revenue + total
    
    # SQL Injection vulnerability
    import sqlite3
    conn = sqlite3.connect('orders.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO orders VALUES ('%s', %s)" % (order_id, total))
    conn.commit()
    
    return total
    # Unreachable code
    print("Order processed!")
    log_order(order_id)


def calculate_shipping(weight, destination):
    """Calculate shipping cost."""
    # Missing return on some paths
    if weight <= 0:
        return
    
    if destination == None:  # Should use 'is None'
        raise ValueError("Destination required")
    
    rates = {"domestic": 5.99, "international": 15.99}
    
    if destination in rates:
        cost = rates[destination] * weight
        return cost


def get_user_data(user_id):
    """Fetch user data - demonstrates resource leak."""
    f = open("users.json", "r")
    data = f.read()
    # File never closed - resource leak
    
    # Using eval on external data
    user = eval(data)
    
    for u in user:
        if u['id'] == True:  # Comparing with boolean literal
            return u
    return None


def validate_email(email):
    """Validate email address."""
    try:
        parts = email.split('@')
        if len(parts) != 2:
            raise ValueError("Invalid email")
        return True
    except:  # Bare except
        pass  # Silently swallowing exception


def apply_bulk_discount(orders, threshold=1000):
    """Apply bulk discount to orders."""
    list = []  # Shadowing built-in
    
    for order in orders:
        if order['total'] > threshold:
            if order['customer_type'] == 'premium':
                if order['region'] == 'domestic':
                    if order['payment_verified'] == True:
                        # Deep nesting
                        discount = order['total'] * 0.15
                        list.append(discount)
    
    return list


def infinite_retry(operation):
    """Retry an operation - potential infinite loop."""
    while True:
        try:
            result = operation()
            if result == False:
                continue
        except Exception:
            pass  # Swallow and retry forever


class OrderManager:
    """Manages orders with various anti-patterns."""
    
    def __init__(self, config={}):
        self.config = config
        self.orders = []
    
    def add_order(self, order):
        self.orders.append(order)
        
    def get_total(self):
        sum = 0  # Shadowing built-in
        for order in self.orders:
            sum += order.get('total', 0)
        return sum
    
    def export_orders(self):
        """Export orders to file."""
        assert len(self.orders) > 0
        assert self.config is not None
        assert isinstance(self.orders, list)
        assert all('total' in o for o in self.orders)
        # Heavy use of assertions for validation
        
        f = open("orders_export.csv", "w")
        for order in self.orders:
            f.write(f"{order}\\n")
'''


SAMPLE_BUGGY_CODE_2 = '''"""
Authentication Module - Contains security vulnerabilities
"""

import hashlib
import pickle

SECRET_KEY = "my_secret_key_12345"
admin_password = "admin123"

def authenticate(username, password):
    """Authenticate a user."""
    # Weak hashing
    hashed = hashlib.md5(password.encode()).hexdigest()
    
    # SQL Injection
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
    cursor.execute(query)
    
    try:
        user = cursor.fetchone()
        if user:
            return True
        return False
    except:
        pass


def deserialize_session(data):
    """Load session from serialized data."""
    # Dangerous deserialization
    session = pickle.loads(data)
    return session


def check_admin(user_role):
    """Check if user is admin."""
    if type(user_role) == str:
        if user_role == "admin":
            return True
    return False


def generate_token(user_id, secret="default_secret_token_value"):
    """Generate auth token."""
    token = hashlib.sha1(f"{user_id}{secret}".encode()).hexdigest()
    return token


def run_user_command(command):
    """Execute a user-provided command."""
    result = eval(command)
    return result
'''


SAMPLE_BUGGY_CODE_3 = '''"""
Data Processing Pipeline - Performance and reliability issues
"""

import time
from datetime import datetime

processed_items = []
error_count = 0

def process_batch(items=[], batch_size=100):
    """Process a batch of items."""
    global error_count
    global processed_items
    
    results = []
    
    for i in range(len(items)):
        item = items[i]
        try:
            result = transform(item)
            results.append(result)
            processed_items.append(result)
        except:
            error_count += 1
            pass
    
    return results


def transform(item):
    """Transform a data item."""
    if item == None:
        return
    
    if type(item) == dict:
        output = {}
        for key in item:
            if key == "timestamp":
                output[key] = str(item[key])
            elif key == "value":
                output[key] = float(item[key])
            else:
                output[key] = item[key]
        return output
    
    return str(item)


def find_duplicates(items):
    """Find duplicate items - O(n²) approach."""
    duplicates = []
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            if items[i] == items[j]:
                if items[i] not in duplicates:
                    duplicates.append(items[i])
    return duplicates


def load_config(path):
    """Load configuration file."""
    f = open(path, "r")
    config = eval(f.read())
    return config
    f.close()  # Unreachable


def retry_forever(func):
    """Retry a function until it succeeds."""
    while True:
        try:
            return func()
        except Exception:
            time.sleep(1)
'''


SAMPLE_FILES = {
    "🛒 E-Commerce Order System (order_processor.py)": SAMPLE_BUGGY_CODE,
    "🔐 Authentication Module (auth.py)": SAMPLE_BUGGY_CODE_2,
    "📊 Data Processing Pipeline (pipeline.py)": SAMPLE_BUGGY_CODE_3,
}

SAMPLE_REQUIREMENTS = """# Production Requirements (Legacy API Service)
# Vulnerable to OWASP 2025 A06 Supply-Chain risks
requests==2.25.1
urllib3==1.26.15
django==3.2.20
pyyaml==5.3.1
flask==2.0.1
pillow==9.5.0
jinja2==2.11.3
cryptography==3.4.8
numpy==1.21.5
pydantic
gunicorn
"""

SAMPLE_MULTI_PROJECT = {
    "services/order_service.py": SAMPLE_BUGGY_CODE,
    "auth/auth_manager.py": SAMPLE_BUGGY_CODE_2,
    "etl/pipeline_worker.py": SAMPLE_BUGGY_CODE_3,
}

__all__ = [
    "SEVERITY_COLORS",
    "SEVERITY_EMOJIS",
    "CATEGORY_ICONS",
    "risk_color",
    "risk_label",
    "complexity_color",
    "SAMPLE_FILES",
    "SAMPLE_REQUIREMENTS",
    "SAMPLE_MULTI_PROJECT",
    "SAMPLE_BUGGY_CODE",
    "SAMPLE_BUGGY_CODE_2",
    "SAMPLE_BUGGY_CODE_3",
]
