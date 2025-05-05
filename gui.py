from PIL import Image, ImageTk
import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from main import *
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
import numpy as np
import ssl
import hashlib
import time

class KeystrokeAnalyzer:
    def __init__(self):
        self.timings = []
        self.last_key_time = None
        self.model = None
        self.kmeans = None
    
    def record_keystroke(self, event):
        current_time = time.time()
        if self.last_key_time is not None:
            self.timings.append(current_time - self.last_key_time)
        self.last_key_time = current_time
    
    def train_models(self):
        if len(self.timings) < 10:
            return False
        
        X = np.array(self.timings).reshape(-1, 1)
        
        # Isolation Forest for anomaly detection
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.model.fit(X)
        
        # K-means for clustering
        self.kmeans = KMeans(n_clusters=2, random_state=42)
        self.kmeans.fit(X)
        
        return True
    
    def analyze_keystroke(self, current_timing):
        if self.model is None or self.kmeans is None:
            return True  # Allow if models not trained
        
        X = np.array([current_timing]).reshape(-1, 1)
        
        # Check with Isolation Forest
        is_inlier = self.model.predict(X)[0] == 1
        
        # Check with K-means (compare to largest cluster)
        cluster = self.kmeans.predict(X)[0]
        largest_cluster = np.argmax(np.bincount(self.kmeans.labels_))
        
        return is_inlier and (cluster == largest_cluster)

keystroke_analyzer = KeystrokeAnalyzer()

class MainAdminDashboard:
    def __init__(self, username, token):
        self.username = username
        self.token = token
        self.window = tk.Toplevel()
        self.window.title("Main Admin Dashboard")
        self.window.geometry("900x700")
        self.window.configure(bg="#161612")

        # Title with welcome message
        title_frame = tk.Frame(self.window, bg="#161612")
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(title_frame, text=f"Main Admin Dashboard - Welcome {username}", 
                font=("JetBrains Mono", 20, "bold"), bg="#161612", fg="#D9AE64").pack(side=tk.LEFT, padx=20, pady=10)
        
        # Logout button
        tk.Button(title_frame, text="Logout", command=self.logout, 
                 bg="#C4452A", fg="#ffffff", font=("JetBrains Mono", 12), bd=0).pack(side=tk.RIGHT, padx=20, pady=10)

        # Main frame
        main_frame = tk.Frame(self.window, bg="#161612", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Buttons
        button_style = {
            'bg': '#115156',
            'fg': '#ffffff',
            'font': ('JetBrains Mono', 12),
            'padx': 20,
            'pady': 10,
            'bd': 0,
            'activebackground': '#187177',
            'activeforeground': '#ffffff'
        }

        tk.Button(main_frame, text="Add Admin", command=self.add_admin, **button_style).pack(pady=10)
        tk.Button(main_frame, text="Update Admin Details", command=self.update_admin, **button_style).pack(pady=10)
        tk.Button(main_frame, text="Add User", command=self.add_user, **button_style).pack(pady=10)
        tk.Button(main_frame, text="Update User Details", command=self.update_user, **button_style).pack(pady=10)
        tk.Button(main_frame, text="View Login Statistics", 
                command=lambda: self.show_login_stats(main_frame), **button_style).pack(pady=10)
        tk.Button(main_frame, text="View Security Analytics", 
                command=lambda: self.show_security_analytics(main_frame), **button_style).pack(pady=10)

        # Demo data controls
        demo_frame = tk.Frame(main_frame, bg="#161612")
        demo_frame.pack(pady=10)
        
        demo_button_style = {
            'bg': '#115156',
            'fg': '#ffffff',
            'font': ('JetBrains Mono', 12),
            'padx': 10,
            'pady': 5,
            'bd': 0,
            'activebackground': '#187177',
            'activeforeground': '#ffffff'
        }
        
        tk.Button(demo_frame, text="Load Demo Data", command=self.load_demo_data, **demo_button_style).pack(side=tk.LEFT, padx=5)
        tk.Button(demo_frame, text="Reset Demo Data", command=self.reset_demo_data, **demo_button_style).pack(side=tk.LEFT, padx=5)
        tk.Button(demo_frame, text="Clear All Data", command=self.clear_all_data, **demo_button_style).pack(side=tk.LEFT, padx=5)

        # Session check
        self.check_session()

    def check_session(self):
        if not validate_session(self.token):
            messagebox.showwarning("Session Expired", "Your session has expired. Please login again.")
            self.window.destroy()
            return
        self.window.after(60000, self.check_session)

    def logout(self):
        logout_session(self.token)
        self.window.destroy()
        messagebox.showinfo("Logged Out", "You have been successfully logged out.")

    def load_demo_data(self):
        if load_demo_data():
            messagebox.showinfo("Success", "Demo data loaded successfully!")
        else:
            messagebox.showerror("Error", "Failed to load demo data!")

    def reset_demo_data(self):
        if reset_demo_data():
            messagebox.showinfo("Success", "Demo data reset successfully!")
        else:
            messagebox.showerror("Error", "Failed to reset demo data!")

    def clear_all_data(self):
        if messagebox.askyesno("Confirm", "This will delete ALL data except admin accounts. Continue?"):
            if clear_all_data():
                messagebox.showinfo("Success", "All data cleared successfully!")
            else:
                messagebox.showerror("Error", "Failed to clear data!")

    def show_security_analytics(self, main_frame):
      main_frame.pack_forget()
    
      analytics_frame = tk.Frame(self.window, bg="#161612", padx=20, pady=20)
      analytics_frame.pack(fill=tk.BOTH, expand=True)
    
      stats = get_security_analytics()
    
    # Display summary
      tk.Label(analytics_frame, text="Security Analytics Dashboard", font=("JetBrains Mono", 16, "bold"), 
            bg="#161612", fg="#D9AE64").pack(pady=10)
    
    # Anomalies summary
      tk.Label(analytics_frame, text="Security Anomalies Detected:", 
            bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12, "bold")).pack(anchor="w", pady=5)
    
      tk.Label(analytics_frame, text=f"Fingerprint Anomalies: {stats['anomalies']['fingerprint']}", 
            bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
    
      tk.Label(analytics_frame, text=f"Impossible Travel Events: {stats['anomalies']['velocity']}", 
            bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
    
      tk.Label(analytics_frame, text=f"Suspicious Process Incidents: {stats['anomalies']['suspicious_processes']}", 
            bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
    
    # Create a figure for the anomaly chart
      fig1, ax1 = plt.subplots(figsize=(8, 4))
      anomalies = ['Fingerprint', 'Travel', 'Processes']
      counts = [
        stats['anomalies']['fingerprint'],
        stats['anomalies']['velocity'],
        stats['anomalies']['suspicious_processes']
      ]
    
      ax1.bar(anomalies, counts, color=['#277C5A', '#C4452A', '#D9AE64'])
      ax1.set_title('Security Anomalies', color='white')
      ax1.set_ylabel('Count', color='white')
      ax1.set_facecolor('#161612')
      fig1.patch.set_facecolor('#161612')
      ax1.tick_params(colors='white')
    
    # Embed the plot in the Tkinter window
      canvas1 = FigureCanvasTkAgg(fig1, master=analytics_frame)
      canvas1.draw()
      canvas1.get_tk_widget().pack(pady=20)
    
    # Back button
      tk.Button(analytics_frame, text="Back", 
             command=lambda: [analytics_frame.destroy(), main_frame.pack(fill=tk.BOTH, expand=True)],
             bg="#115156", fg="#ffffff", font=("JetBrains Mono", 12), bd=0).pack(pady=10)

    def show_login_stats(self, main_frame):
        main_frame.pack_forget()
        
        stats_frame = tk.Frame(self.window, bg="#161612", padx=20, pady=20)
        stats_frame.pack(fill=tk.BOTH, expand=True)
        
        stats = get_login_stats()
        
        # Display summary
        tk.Label(stats_frame, text="Login Attempt Statistics", font=("JetBrains Mono", 16, "bold"), 
                bg="#161612", fg="#D9AE64").pack(pady=10)
        
        tk.Label(stats_frame, text=f"Total Attempts: {stats['total_attempts']}", 
                bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
        
        for status, count in stats["status_counts"].items():
            tk.Label(stats_frame, text=f"{status}: {count}", 
                    bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
        
        # Create a figure for the chart
        fig, ax = plt.subplots(figsize=(8, 4))
        statuses = list(stats["status_counts"].keys())
        counts = list(stats["status_counts"].values())
        
        ax.bar(statuses, counts, color=['#277C5A', '#C4452A'])
        ax.set_title('Login Attempts by Status', color='white')
        ax.set_ylabel('Count', color='white')
        ax.set_facecolor('#161612')
        fig.patch.set_facecolor('#161612')
        ax.tick_params(colors='white')
        
        # Embed the plot in the Tkinter window
        canvas = FigureCanvasTkAgg(fig, master=stats_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(pady=20)
        
        # Recent attempts table
        tk.Label(stats_frame, text="Recent Login Attempts:", 
                bg="#161612", fg="#D9AE64", font=("JetBrains Mono", 12, "bold")).pack(pady=10)
        
        columns = ("Username", "IP Address", "Status", "Timestamp")
        tree = ttk.Treeview(stats_frame, columns=columns, show="headings", height=5)
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", 
                      background="#161612",
                      foreground="#ffffff",
                      fieldbackground="#161612",
                      font=("JetBrains Mono", 10))
        style.configure("Treeview.Heading", 
                      background="#115156",
                      foreground="#ffffff",
                      font=("JetBrains Mono", 10, "bold"))
        style.map('Treeview', background=[('selected', '#187177')])
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)
        
        for attempt in stats["recent_attempts"]:
            tree.insert("", "end", values=attempt)
        
        tree.pack(pady=10)

        # Back button
        tk.Button(stats_frame, text="Back", 
                 command=lambda: [stats_frame.destroy(), main_frame.pack(fill=tk.BOTH, expand=True)],
                 bg="#115156", fg="#ffffff", font=("JetBrains Mono", 12), bd=0).pack(pady=10)

    def add_admin(self):
        add_window = tk.Toplevel()
        add_window.title("Add Admin")
        add_window.configure(bg="#161612")

        tk.Label(add_window, text="Username:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=0, column=0, sticky="e", padx=10, pady=5)
        entry_username = tk.Entry(add_window, width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_username.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(add_window, text="Password:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=1, column=0, sticky="e", padx=10, pady=5)
        entry_password = tk.Entry(add_window, show="*", width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_password.grid(row=1, column=1, padx=10, pady=5)

        tk.Label(add_window, text="Role:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=2, column=0, sticky="e", padx=10, pady=5)
        entry_role = ttk.Combobox(add_window, values=["Main Admin", "Admin"], font=("JetBrains Mono", 12))
        entry_role.grid(row=2, column=1, padx=10, pady=5)
        entry_role.set("Admin")

        button_style = {
            'bg': '#115156',
            'fg': '#ffffff',
            'font': ('JetBrains Mono', 12),
            'padx': 20,
            'pady': 10,
            'bd': 0,
            'activebackground': '#187177',
            'activeforeground': '#ffffff'
        }

        tk.Button(add_window, text="Add", command=lambda: self.save_admin(
            entry_username.get(), entry_password.get(), entry_role.get(), add_window), **button_style).grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    def save_admin(self, username, password, role, window):
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required!")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long!")
            return
        
        hashed_password = hash_password(password)
        
        conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO admins (username, password, role) VALUES (?, ?, ?)",
                          (username, hashed_password, role))
            conn.commit()
            messagebox.showinfo("Success", "Admin added successfully!")
            window.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists!")
        conn.close()

    def update_admin(self):
        update_window = tk.Toplevel()
        update_window.title("Update Admin Details")
        update_window.configure(bg="#161612")

        tk.Label(update_window, text="Username:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=0, column=0, sticky="e", padx=10, pady=5)
        entry_username = tk.Entry(update_window, width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_username.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(update_window, text="New Password:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=1, column=0, sticky="e", padx=10, pady=5)
        entry_password = tk.Entry(update_window, show="*", width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_password.grid(row=1, column=1, padx=10, pady=5)

        button_style = {
            'bg': '#115156',
            'fg': '#ffffff',
            'font': ('JetBrains Mono', 12),
            'padx': 20,
            'pady': 10,
            'bd': 0,
            'activebackground': '#187177',
            'activeforeground': '#ffffff'
        }

        tk.Button(update_window, text="Update", command=lambda: self.save_admin_update(
            entry_username.get(), entry_password.get(), update_window), **button_style).grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def save_admin_update(self, username, password, window):
        if not username:
            messagebox.showerror("Error", "Username is required!")
            return
        
        if password and len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long!")
            return
        
        hashed_password = hash_password(password) if password else None
        
        conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()
        
        if hashed_password:
            cursor.execute("UPDATE admins SET password = ? WHERE username = ?", (hashed_password, username))
        else:
            messagebox.showerror("Error", "No password provided!")
            conn.close()
            return
        
        conn.commit()
        if cursor.rowcount > 0:
            messagebox.showinfo("Success", "Admin details updated successfully!")
            window.destroy()
        else:
            messagebox.showerror("Error", "Username not found!")
        conn.close()

    def add_user(self):
        add_window = tk.Toplevel()
        add_window.title("Add User")
        add_window.configure(bg="#161612")

        tk.Label(add_window, text="Username:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=0, column=0, sticky="e", padx=10, pady=5)
        entry_username = tk.Entry(add_window, width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_username.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(add_window, text="Password:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=1, column=0, sticky="e", padx=10, pady=5)
        entry_password = tk.Entry(add_window, show="*", width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_password.grid(row=1, column=1, padx=10, pady=5)

        button_style = {
            'bg': '#115156',
            'fg': '#ffffff',
            'font': ('JetBrains Mono', 12),
            'padx': 20,
            'pady': 10,
            'bd': 0,
            'activebackground': '#187177',
            'activeforeground': '#ffffff'
        }

        tk.Button(add_window, text="Add", command=lambda: self.save_user(
            entry_username.get(), entry_password.get(), add_window), **button_style).grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def save_user(self, username, password, window):
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required!")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long!")
            return
        
        hashed_password = hash_password(password)
        
        conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()
        
        # Get the admin ID
        cursor.execute("SELECT id FROM admins WHERE username = ?", (self.username,))
        admin_id = cursor.fetchone()[0]
        
        try:
            cursor.execute("INSERT INTO users (username, password, admin_id) VALUES (?, ?, ?)",
                          (username, hashed_password, admin_id))
            conn.commit()
            messagebox.showinfo("Success", "User added successfully!")
            window.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists!")
        conn.close()

    def update_user(self):
        update_window = tk.Toplevel()
        update_window.title("Update User Details")
        update_window.configure(bg="#161612")

        tk.Label(update_window, text="Username:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=0, column=0, sticky="e", padx=10, pady=5)
        entry_username = tk.Entry(update_window, width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_username.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(update_window, text="New Password:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=1, column=0, sticky="e", padx=10, pady=5)
        entry_password = tk.Entry(update_window, show="*", width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_password.grid(row=1, column=1, padx=10, pady=5)

        button_style = {
            'bg': '#115156',
            'fg': '#ffffff',
            'font': ('JetBrains Mono', 12),
            'padx': 20,
            'pady': 10,
            'bd': 0,
            'activebackground': '#187177',
            'activeforeground': '#ffffff'
        }

        tk.Button(update_window, text="Update", command=lambda: self.save_user_update(
            entry_username.get(), entry_password.get(), update_window), **button_style).grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def save_user_update(self, username, password, window):
        if not username:
            messagebox.showerror("Error", "Username is required!")
            return
        
        if password and len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long!")
            return
        
        hashed_password = hash_password(password) if password else None
        
        conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()
        
        if hashed_password:
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
        else:
            messagebox.showerror("Error", "No password provided!")
            conn.close()
            return
        
        conn.commit()
        if cursor.rowcount > 0:
            messagebox.showinfo("Success", "User details updated successfully!")
            window.destroy()
        else:
            messagebox.showerror("Error", "Username not found!")
        conn.close()

class AdminDashboard:
    def __init__(self, username, token):
        self.username = username
        self.token = token
        self.window = tk.Toplevel()
        self.window.title("Admin Dashboard")
        self.window.geometry("900x700")
        self.window.configure(bg="#161612")

        # Title with welcome message
        title_frame = tk.Frame(self.window, bg="#161612")
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(title_frame, text=f"Admin Dashboard - Welcome {username}", 
                font=("JetBrains Mono", 20, "bold"), bg="#161612", fg="#D9AE64").pack(side=tk.LEFT, padx=20, pady=10)
        
        # Logout button
        tk.Button(title_frame, text="Logout", command=self.logout, 
                 bg="#C4452A", fg="#ffffff", font=("JetBrains Mono", 12), bd=0).pack(side=tk.RIGHT, padx=20, pady=10)

        # Main frame
        main_frame = tk.Frame(self.window, bg="#161612", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Buttons
        button_style = {
            'bg': '#115156',
            'fg': '#ffffff',
            'font': ('JetBrains Mono', 12),
            'padx': 20,
            'pady': 10,
            'bd': 0,
            'activebackground': '#187177',
            'activeforeground': '#ffffff'
        }

        tk.Button(main_frame, text="Add User", command=self.add_user, **button_style).pack(pady=10)
        tk.Button(main_frame, text="Update User Details", command=self.update_user, **button_style).pack(pady=10)
        tk.Button(main_frame, text="View Login Statistics", 
                command=lambda: self.show_login_stats(main_frame), **button_style).pack(pady=10)
        tk.Button(main_frame, text="View Security Analytics", 
                command=lambda: self.show_security_analytics(main_frame), **button_style).pack(pady=10)

        # Demo data controls
        demo_frame = tk.Frame(main_frame, bg="#161612")
        demo_frame.pack(pady=10)
        
        demo_button_style = {
            'bg': '#115156',
            'fg': '#ffffff',
            'font': ('JetBrains Mono', 12),
            'padx': 10,
            'pady': 5,
            'bd': 0,
            'activebackground': '#187177',
            'activeforeground': '#ffffff'
        }
        
        tk.Button(demo_frame, text="Load Demo Data", command=self.load_demo_data, **demo_button_style).pack(side=tk.LEFT, padx=5)
        tk.Button(demo_frame, text="Reset Demo Data", command=self.reset_demo_data, **demo_button_style).pack(side=tk.LEFT, padx=5)
        tk.Button(demo_frame, text="Clear All Data", command=self.clear_all_data, **demo_button_style).pack(side=tk.LEFT, padx=5)

        # Session check
        self.check_session()

    def check_session(self):
        if not validate_session(self.token):
            messagebox.showwarning("Session Expired", "Your session has expired. Please login again.")
            self.window.destroy()
            return
        self.window.after(60000, self.check_session)

    def logout(self):
        logout_session(self.token)
        self.window.destroy()
        messagebox.showinfo("Logged Out", "You have been successfully logged out.")

    def load_demo_data(self):
        if load_demo_data():
            messagebox.showinfo("Success", "Demo data loaded successfully!")
        else:
            messagebox.showerror("Error", "Failed to load demo data!")

    def reset_demo_data(self):
        if reset_demo_data():
            messagebox.showinfo("Success", "Demo data reset successfully!")
        else:
            messagebox.showerror("Error", "Failed to reset demo data!")

    def clear_all_data(self):
        if messagebox.askyesno("Confirm", "This will delete ALL data except admin accounts. Continue?"):
            if clear_all_data():
                messagebox.showinfo("Success", "All data cleared successfully!")
            else:
                messagebox.showerror("Error", "Failed to clear data!")

    def show_security_analytics(self, main_frame):
        main_frame.pack_forget()
    
        analytics_frame = tk.Frame(self.window, bg="#161612", padx=20, pady=20)
        analytics_frame.pack(fill=tk.BOTH, expand=True)
    
        stats = get_security_analytics()
    
    # Display summary
        tk.Label(analytics_frame, text="Security Analytics Dashboard", font=("JetBrains Mono", 16, "bold"), 
            bg="#161612", fg="#D9AE64").pack(pady=10)
    
    # Anomalies summary
        tk.Label(analytics_frame, text="Security Anomalies Detected:", 
            bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12, "bold")).pack(anchor="w", pady=5)
    
        tk.Label(analytics_frame, text=f"Fingerprint Anomalies: {stats['anomalies']['fingerprint']}", 
            bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
    
        tk.Label(analytics_frame, text=f"Impossible Travel Events: {stats['anomalies']['velocity']}", 
            bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
    
        tk.Label(analytics_frame, text=f"Suspicious Process Incidents: {stats['anomalies']['suspicious_processes']}", 
            bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
    
    # Create a figure for the anomaly chart
        fig1, ax1 = plt.subplots(figsize=(8, 4))
        anomalies = ['Fingerprint', 'Travel', 'Processes']
        counts = [
           stats['anomalies']['fingerprint'],
           stats['anomalies']['velocity'],
           stats['anomalies']['suspicious_processes']
        ]
    
        ax1.bar(anomalies, counts, color=['#277C5A', '#C4452A', '#D9AE64'])
        ax1.set_title('Security Anomalies', color='white')
        ax1.set_ylabel('Count', color='white')
        ax1.set_facecolor('#161612')
        fig1.patch.set_facecolor('#161612')
        ax1.tick_params(colors='white')
    
    # Embed the plot in the Tkinter window
        canvas1 = FigureCanvasTkAgg(fig1, master=analytics_frame)
        canvas1.draw()
        canvas1.get_tk_widget().pack(pady=20)
    
    # Back button
        tk.Button(analytics_frame, text="Back", 
             command=lambda: [analytics_frame.destroy(), main_frame.pack(fill=tk.BOTH, expand=True)],
             bg="#115156", fg="#ffffff", font=("JetBrains Mono", 12), bd=0).pack(pady=10)

    def show_login_stats(self, main_frame):
        main_frame.pack_forget()
        
        stats_frame = tk.Frame(self.window, bg="#161612", padx=20, pady=20)
        stats_frame.pack(fill=tk.BOTH, expand=True)
        
        stats = get_login_stats()
        
        # Display summary
        tk.Label(stats_frame, text="Login Attempt Statistics", font=("JetBrains Mono", 16, "bold"), 
                bg="#161612", fg="#D9AE64").pack(pady=10)
        
        tk.Label(stats_frame, text=f"Total Attempts: {stats['total_attempts']}", 
                bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
        
        for status, count in stats["status_counts"].items():
            tk.Label(stats_frame, text=f"{status}: {count}", 
                    bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
        
        # Create a figure for the chart
        fig, ax = plt.subplots(figsize=(8, 4))
        statuses = list(stats["status_counts"].keys())
        counts = list(stats["status_counts"].values())
        
        ax.bar(statuses, counts, color=['#277C5A', '#C4452A'])
        ax.set_title('Login Attempts by Status', color='white')
        ax.set_ylabel('Count', color='white')
        ax.set_facecolor('#161612')
        fig.patch.set_facecolor('#161612')
        ax.tick_params(colors='white')
        
        # Embed the plot in the Tkinter window
        canvas = FigureCanvasTkAgg(fig, master=stats_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(pady=20)
        
        # Recent attempts table
        tk.Label(stats_frame, text="Recent Login Attempts:", 
                bg="#161612", fg="#D9AE64", font=("JetBrains Mono", 12, "bold")).pack(pady=10)
        
        columns = ("Username", "IP Address", "Status", "Timestamp")
        tree = ttk.Treeview(stats_frame, columns=columns, show="headings", height=5)
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", 
                      background="#161612",
                      foreground="#ffffff",
                      fieldbackground="#161612",
                      font=("JetBrains Mono", 10))
        style.configure("Treeview.Heading", 
                      background="#115156",
                      foreground="#ffffff",
                      font=("JetBrains Mono", 10, "bold"))
        style.map('Treeview', background=[('selected', '#187177')])
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)
        
        for attempt in stats["recent_attempts"]:
            tree.insert("", "end", values=attempt)
        
        tree.pack(pady=10)

        # Back button
        tk.Button(stats_frame, text="Back", 
                 command=lambda: [stats_frame.destroy(), main_frame.pack(fill=tk.BOTH, expand=True)],
                 bg="#115156", fg="#ffffff", font=("JetBrains Mono", 12), bd=0).pack(pady=10)

    def add_user(self):
        add_window = tk.Toplevel()
        add_window.title("Add User")
        add_window.configure(bg="#161612")

        tk.Label(add_window, text="Username:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=0, column=0, sticky="e", padx=10, pady=5)
        entry_username = tk.Entry(add_window, width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_username.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(add_window, text="Password:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=1, column=0, sticky="e", padx=10, pady=5)
        entry_password = tk.Entry(add_window, show="*", width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_password.grid(row=1, column=1, padx=10, pady=5)

        button_style = {
            'bg': '#115156',
            'fg': '#ffffff',
            'font': ('JetBrains Mono', 12),
            'padx': 20,
            'pady': 10,
            'bd': 0,
            'activebackground': '#187177',
            'activeforeground': '#ffffff'
        }

        tk.Button(add_window, text="Add", command=lambda: self.save_user(
            entry_username.get(), entry_password.get(), add_window), **button_style).grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def save_user(self, username, password, window):
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required!")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long!")
            return
        
        hashed_password = hash_password(password)
        
        conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()
        
        # Get the admin ID
        cursor.execute("SELECT id FROM admins WHERE username = ?", (self.username,))
        admin_id = cursor.fetchone()[0]
        
        try:
            cursor.execute("INSERT INTO users (username, password, admin_id) VALUES (?, ?, ?)",
                          (username, hashed_password, admin_id))
            conn.commit()
            messagebox.showinfo("Success", "User added successfully!")
            window.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists!")
        conn.close()

    def update_user(self):
        update_window = tk.Toplevel()
        update_window.title("Update User Details")
        update_window.configure(bg="#161612")

        tk.Label(update_window, text="Username:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=0, column=0, sticky="e", padx=10, pady=5)
        entry_username = tk.Entry(update_window, width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_username.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(update_window, text="New Password:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=1, column=0, sticky="e", padx=10, pady=5)
        entry_password = tk.Entry(update_window, show="*", width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_password.grid(row=1, column=1, padx=10, pady=5)

        button_style = {
            'bg': '#115156',
            'fg': '#ffffff',
            'font': ('JetBrains Mono', 12),
            'padx': 20,
            'pady': 10,
            'bd': 0,
            'activebackground': '#187177',
            'activeforeground': '#ffffff'
        }

        tk.Button(update_window, text="Update", command=lambda: self.save_user_update(
            entry_username.get(), entry_password.get(), update_window), **button_style).grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def save_user_update(self, username, password, window):
        if not username:
            messagebox.showerror("Error", "Username is required!")
            return
        
        if password and len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long!")
            return
        
        hashed_password = hash_password(password) if password else None
        
        conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()
        
        if hashed_password:
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
        else:
            messagebox.showerror("Error", "No password provided!")
            conn.close()
            return
        
        conn.commit()
        if cursor.rowcount > 0:
            messagebox.showinfo("Success", "User details updated successfully!")
            window.destroy()
        else:
            messagebox.showerror("Error", "Username not found!")
        conn.close()

class UserDashboard:
    def __init__(self, username, token):
        self.username = username
        self.token = token
        self.window = tk.Toplevel()
        self.window.title("User Dashboard")
        self.window.geometry("900x700")
        self.window.configure(bg="#161612")

        # Title with welcome message
        title_frame = tk.Frame(self.window, bg="#161612")
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(title_frame, text=f"User Dashboard - Welcome {username}", 
                font=("JetBrains Mono", 20, "bold"), bg="#161612", fg="#D9AE64").pack(side=tk.LEFT, padx=20, pady=10)
        
        # Logout button
        tk.Button(title_frame, text="Logout", command=self.logout, 
                 bg="#C4452A", fg="#ffffff", font=("JetBrains Mono", 12), bd=0).pack(side=tk.RIGHT, padx=20, pady=10)

        # Main frame
        main_frame = tk.Frame(self.window, bg="#161612", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Buttons
        button_style = {
            'bg': '#115156',
            'fg': '#ffffff',
            'font': ('JetBrains Mono', 12),
            'padx': 20,
            'pady': 10,
            'bd': 0,
            'activebackground': '#187177',
            'activeforeground': '#ffffff'
        }

        tk.Button(main_frame, text="Update My Details", command=self.update_details, **button_style).pack(pady=10)
        tk.Button(main_frame, text="View Login Statistics", 
                command=lambda: self.show_login_stats(main_frame), **button_style).pack(pady=10)
        

        # Session check
        self.check_session()

    def check_session(self):
        if not validate_session(self.token):
            messagebox.showwarning("Session Expired", "Your session has expired. Please login again.")
            self.window.destroy()
            return
        self.window.after(60000, self.check_session)

    def logout(self):
        logout_session(self.token)
        self.window.destroy()
        messagebox.showinfo("Logged Out", "You have been successfully logged out.")

    def show_my_analytics(self, main_frame):
        main_frame.pack_forget()
        
        analytics_frame = tk.Frame(self.window, bg="#161612", padx=20, pady=20)
        analytics_frame.pack(fill=tk.BOTH, expand=True)
        
        stats = get_user_security_analytics(self.username)
        
        # Display summary
        tk.Label(analytics_frame, text="My Security Analytics", font=("JetBrains Mono", 16, "bold"), 
                bg="#161612", fg="#D9AE64").pack(pady=10)
        
        # Anomalies summary
        tk.Label(analytics_frame, text="Security Events Related to My Account:", 
                bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12, "bold")).pack(anchor="w", pady=5)
        
        tk.Label(analytics_frame, text=f"Failed Login Attempts: {stats['failed_attempts']}", 
                bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
        
        tk.Label(analytics_frame, text=f"Fingerprint Changes: {stats['fingerprint_changes']}", 
                bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
        
        tk.Label(analytics_frame, text=f"Impossible Travel Events: {stats['impossible_travel']}", 
                bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
        
        # Create a figure for the anomaly chart
        fig1, ax1 = plt.subplots(figsize=(8, 4))
        anomalies = ['Failed Logins', 'Fingerprint', 'Travel']
        counts = [
            stats['failed_attempts'],
            stats['fingerprint_changes'],
            stats['impossible_travel']
        ]
        
        ax1.bar(anomalies, counts, color=['#C4452A', '#D9AE64', '#277C5A'])
        ax1.set_title('My Security Events', color='white')
        ax1.set_ylabel('Count', color='white')
        ax1.set_facecolor('#161612')
        fig1.patch.set_facecolor('#161612')
        ax1.tick_params(colors='white')
        
        # Embed the plot in the Tkinter window
        canvas1 = FigureCanvasTkAgg(fig1, master=analytics_frame)
        canvas1.draw()
        canvas1.get_tk_widget().pack(pady=20)
        
        # Back button
        tk.Button(analytics_frame, text="Back", 
                 command=lambda: [analytics_frame.destroy(), main_frame.pack(fill=tk.BOTH, expand=True)],
                 bg="#115156", fg="#ffffff", font=("JetBrains Mono", 12), bd=0).pack(pady=10)

    def show_login_stats(self, main_frame):
        main_frame.pack_forget()
        
        stats_frame = tk.Frame(self.window, bg="#161612", padx=20, pady=20)
        stats_frame.pack(fill=tk.BOTH, expand=True)
        
        stats = get_login_stats()
        
        # Display summary
        tk.Label(stats_frame, text="Login Attempt Statistics", font=("JetBrains Mono", 16, "bold"), 
                bg="#161612", fg="#D9AE64").pack(pady=10)
        
        tk.Label(stats_frame, text=f"Total Attempts: {stats['total_attempts']}", 
                bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
        
        for status, count in stats["status_counts"].items():
            tk.Label(stats_frame, text=f"{status}: {count}", 
                    bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).pack(anchor="w")
        
        # Create a figure for the chart
        fig, ax = plt.subplots(figsize=(8, 4))
        statuses = list(stats["status_counts"].keys())
        counts = list(stats["status_counts"].values())
        
        ax.bar(statuses, counts, color=['#277C5A', '#C4452A'])
        ax.set_title('Login Attempts by Status', color='white')
        ax.set_ylabel('Count', color='white')
        ax.set_facecolor('#161612')
        fig.patch.set_facecolor('#161612')
        ax.tick_params(colors='white')
        
        # Embed the plot in the Tkinter window
        canvas = FigureCanvasTkAgg(fig, master=stats_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(pady=20)
        
        # Recent attempts table
        tk.Label(stats_frame, text="Recent Login Attempts:", 
                bg="#161612", fg="#D9AE64", font=("JetBrains Mono", 12, "bold")).pack(pady=10)
        
        columns = ("Username", "IP Address", "Status", "Timestamp")
        tree = ttk.Treeview(stats_frame, columns=columns, show="headings", height=5)
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", 
                      background="#161612",
                      foreground="#ffffff",
                      fieldbackground="#161612",
                      font=("JetBrains Mono", 10))
        style.configure("Treeview.Heading", 
                      background="#115156",
                      foreground="#ffffff",
                      font=("JetBrains Mono", 10, "bold"))
        style.map('Treeview', background=[('selected', '#187177')])
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)
        
        for attempt in stats["recent_attempts"]:
            tree.insert("", "end", values=attempt)
        
        tree.pack(pady=10)

        # Back button
        tk.Button(stats_frame, text="Back", 
                 command=lambda: [stats_frame.destroy(), main_frame.pack(fill=tk.BOTH, expand=True)],
                 bg="#115156", fg="#ffffff", font=("JetBrains Mono", 12), bd=0).pack(pady=10)

    def update_details(self):
        update_window = tk.Toplevel()
        update_window.title("Update My Details")
        update_window.configure(bg="#161612")

        tk.Label(update_window, text="New Password:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=0, column=0, sticky="e", padx=10, pady=5)
        entry_password = tk.Entry(update_window, show="*", width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_password.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(update_window, text="Confirm Password:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=1, column=0, sticky="e", padx=10, pady=5)
        entry_confirm = tk.Entry(update_window, show="*", width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
        entry_confirm.grid(row=1, column=1, padx=10, pady=5)

        button_style = {
            'bg': '#115156',
            'fg': '#ffffff',
            'font': ('JetBrains Mono', 12),
            'padx': 20,
            'pady': 10,
            'bd': 0,
            'activebackground': '#187177',
            'activeforeground': '#ffffff'
        }

        tk.Button(update_window, text="Update", command=lambda: self.save_user_update(
            entry_password.get(), entry_confirm.get(), update_window), **button_style).grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def save_user_update(self, password, confirm_password, window):
        if not password or not confirm_password:
            messagebox.showerror("Error", "Both password fields are required!")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long!")
            return
        
        hashed_password = hash_password(password)
        
        conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, self.username))
        conn.commit()
        
        if cursor.rowcount > 0:
            messagebox.showinfo("Success", "Your details updated successfully!")
            window.destroy()
        else:
            messagebox.showerror("Error", "Failed to update password!")
        conn.close()

def open_dashboard(role, username, token):
    if role == "Main Admin":
        MainAdminDashboard(username, token)
    elif role == "Admin":
        AdminDashboard(username, token)
    elif role == "User":
        UserDashboard(username, token)
    else:
        print("Invalid role detected.")

def handle_login():
    username = entry_username.get().strip()
    password = entry_password.get().strip()
    captcha_input = entry_captcha.get().strip()

    if captcha_input != captcha_text:
        messagebox.showerror("CAPTCHA Failed", "Invalid CAPTCHA! Please try again.")
        generate_new_captcha()
        return

    # Record keystroke timing for password entry(Dont remove this #)
    #if keystroke_analyzer.train_models():
        #current_timing = time.time() - keystroke_analyzer.last_key_time
        #if not keystroke_analyzer.analyze_keystroke(current_timing):
            #messagebox.showwarning("Security Alert", "Unusual typing pattern detected!")
            #log_attempt(username, get_ip_address(), "Failed - Keystroke Anomaly")
            #return

    user_data = validate_credentials(username, password)
    ip_address = get_ip_address()
    
    if user_data:
        # Check for suspicious processes
        suspicious_processes = get_process_list()
        if suspicious_processes:
            messagebox.showwarning("Security Warning", 
                                f"Warning: {len(suspicious_processes)} suspicious processes detected during login!")
        
        # Create a session
        token = create_session(user_data["id"], username, user_data["role"])
        
        messagebox.showinfo("Login Successful", f"Welcome, {user_data['role']} {username}!")
        log_attempt(username, ip_address, "Success")
        open_dashboard(user_data["role"], username, token)
    else:
        messagebox.showerror("Login Failed", "Invalid username or password!")
        log_attempt(username, ip_address, "Failed")
        image_path = capture_image()
        if image_path:
            image_url = upload_to_cloudinary(image_path)
            if image_url:
                sms_message = f"Suspicious login attempt detected. View image: {image_url}"
                send_sms(sms_message)
            send_email(image_path, ip_address)
            lbl_captured_image.config(text=f"Captured Image: {os.path.basename(image_path)}")
            lbl_ip_address.config(text=f"IP Address: {ip_address}")

def generate_new_captcha():
    global captcha_text, captcha_image_path
    captcha_text, captcha_image_path = generate_captcha_image()
    update_captcha_image()

def update_captcha_image():
    captcha_image = Image.open(captcha_image_path)
    captcha_image = captcha_image.resize((200, 80), Image.Resampling.LANCZOS)
    captcha_photo = ImageTk.PhotoImage(captcha_image)
    captcha_image_label.config(image=captcha_photo)
    captcha_image_label.image = captcha_photo

def on_key_press(event):
    keystroke_analyzer.record_keystroke(event)

# GUI Setup
root = tk.Tk()
root.title("Suspicious Activity Tracker - Enhanced Security")
root.geometry("900x700")
root.configure(bg="#161612")

# Title
title_label = tk.Label(root, text="Suspicious Activity Tracker - Enhanced", 
                      font=("JetBrains Mono", 26, "bold"), bg="#115156", fg="#ffffff")
title_label.pack(fill=tk.X, pady=(20, 10))

# Security indicators frame
security_frame = tk.Frame(root, bg="#115156", padx=10, pady=5)
security_frame.pack(fill=tk.X)

# Browser fingerprint indicator
fingerprint = get_browser_fingerprint()
tk.Label(security_frame, text=f"Browser Fingerprint: {fingerprint[:8]}...", bg="#115156", fg="#ffffff", 
        font=("JetBrains Mono", 10)).pack(side=tk.LEFT, padx=5)

# Process monitor
suspicious_processes = get_process_list()
process_status = "🔴" if suspicious_processes else "🟢"
tk.Label(security_frame, text=f"Process Monitor: {process_status} ({len(suspicious_processes)} suspicious)", 
        bg="#115156", fg="#ffffff", font=("JetBrains Mono", 10)).pack(side=tk.RIGHT, padx=5)

# Main frame
main_frame = tk.Frame(root, bg="#161612", padx=20, pady=20)
main_frame.pack(fill=tk.BOTH, expand=True)

# Login Frame
login_frame = tk.Frame(main_frame, bg="#161612")
login_frame.pack(pady=20)

tk.Label(login_frame, text="Username:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=0, column=0, sticky="e", padx=10, pady=5)
entry_username = tk.Entry(login_frame, width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
entry_username.grid(row=0, column=1, padx=10, pady=5)

tk.Label(login_frame, text="Password:", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12)).grid(row=1, column=0, sticky="e", padx=10, pady=5)
entry_password = tk.Entry(login_frame, show="*", width=50, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
entry_password.grid(row=1, column=1, padx=10, pady=5)

# Bind key press events for keystroke dynamics
entry_password.bind("<KeyPress>", on_key_press)

# CAPTCHA Frame
captcha_frame = tk.Frame(login_frame, bg="#161612")
captcha_frame.grid(row=2, column=0, columnspan=2, pady=10)

lbl_captcha = tk.Label(captcha_frame, text="CAPTCHA: ", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12))
lbl_captcha.grid(row=0, column=0, padx=10, pady=5)

entry_captcha = tk.Entry(captcha_frame, width=20, font=("JetBrains Mono", 12), bg="#252525", fg="#ffffff", insertbackground="white")
entry_captcha.grid(row=0, column=1, padx=10, pady=5)

captcha_image_label = tk.Label(captcha_frame, bg="#161612")
captcha_image_label.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

# Refresh CAPTCHA button
tk.Button(captcha_frame, text="Refresh", command=generate_new_captcha,
          bg="#115156", fg="#ffffff", font=("JetBrains Mono", 10), bd=0).grid(row=0, column=2, padx=5)

# Generate initial CAPTCHA
captcha_text, captcha_image_path = generate_captcha_image()
update_captcha_image()

# Login button
login_button = tk.Button(login_frame, text="Login", command=handle_login, 
                        bg="#115156", fg="#ffffff", font=("JetBrains Mono", 12), bd=0,
                        activebackground="#187177", activeforeground="#ffffff")
login_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

# Activity Log Frame
activity_frame = tk.Frame(main_frame, bg="#161612")
activity_frame.pack(pady=20)

lbl_captured_image = tk.Label(activity_frame, text="Captured Image: None", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12))
lbl_captured_image.grid(row=0, column=0, padx=10, pady=5)

lbl_ip_address = tk.Label(activity_frame, text="IP Address: None", bg="#161612", fg="#ffffff", font=("JetBrains Mono", 12))
lbl_ip_address.grid(row=1, column=0, padx=10, pady=5)

# Configure SSL context for secure connections
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = True
ssl_context.verify_mode = ssl.CERT_REQUIRED

def on_closing():
    """Handle window close event"""
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        root.destroy()
        root.quit()  # This ensures complete termination

# Set up the close handler
root.protocol("WM_DELETE_WINDOW", on_closing)

try:
    root.mainloop()
except KeyboardInterrupt:
    print("\nApplication closed by user")
    root.destroy()
    root.quit()