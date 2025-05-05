# gui.py
import tkinter as tk
from tkinter import ttk, messagebox
import threading
from .auth import AuthManager
from .youtube_manager import YouTubeManager
from .detector import SpamDetector
from utils import helpers, constants

class JudolSlayerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Judol Slayer+ | YouTube Comment Spam Remover")
        self.root.geometry("1000x700")
        
        # Initialize managers
        self.auth = AuthManager()
        self.manager = None
        self.detector = SpamDetector()
        
        # Data stores
        self.video_list = []
        self.comment_data = []
        self.current_video_id = ""
        
        # Setup GUI
        self.setup_styles()
        self.create_widgets()
        self.check_saved_token()
        
    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TButton', font=('Helvetica', 10), padding=6)
        self.style.configure('Header.TLabel', font=('Helvetica', 14, 'bold'), foreground='#2c3e50')
        self.style.map('TButton', 
            background=[('active', '#3498db'), ('!disabled', '#2980b9')],
            foreground=[('!disabled', 'white')]
        )

    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Auth Section
        auth_frame = ttk.LabelFrame(main_frame, text=" Authentication ")
        auth_frame.pack(fill=tk.X, pady=10)

        self.login_btn = ttk.Button(auth_frame, text="🔐 Login with Google", command=self.start_login)
        self.login_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.auth_status = ttk.Label(auth_frame, text="Status: Not logged in")
        self.auth_status.pack(side=tk.LEFT, padx=10)

        # Channel Section
        channel_frame = ttk.LabelFrame(main_frame, text=" Channel Configuration ")
        channel_frame.pack(fill=tk.X, pady=10)

        ttk.Label(channel_frame, text="Channel ID/URL:").pack(side=tk.LEFT)
        self.channel_entry = ttk.Entry(channel_entry, width=50)
        self.channel_entry.pack(side=tk.LEFT, padx=5)

        self.fetch_btn = ttk.Button(channel_frame, text="📥 Fetch Videos", command=self.fetch_videos)
        self.fetch_btn.pack(side=tk.LEFT, padx=5)

        # Video Selection
        video_frame = ttk.LabelFrame(main_frame, text=" Video Selection ")
        video_frame.pack(fill=tk.X, pady=10)

        self.video_combo = ttk.Combobox(video_frame, state="readonly")
        self.video_combo.pack(fill=tk.X, padx=5, pady=5)
        self.video_combo.bind("<<ComboboxSelected>>", self.on_video_select)

        # Actions Toolbar
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)

        self.scan_btn = ttk.Button(action_frame, text="🔍 Scan Comments", command=self.scan_comments)
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.detect_btn = ttk.Button(action_frame, text="🧹 Detect Spam", command=self.detect_spam)
        self.detect_btn.pack(side=tk.LEFT, padx=5)

        self.delete_btn = ttk.Button(action_frame, text="🗑️ Delete Selected", command=self.delete_selected)
        self.delete_btn.pack(side=tk.LEFT, padx=5)

        # Comments List
        list_frame = ttk.LabelFrame(main_frame, text=" Comments ")
        list_frame.pack(fill=tk.BOTH, expand=True)

        self.comments_tree = ttk.Treeview(list_frame, columns=('status', 'comment', 'id'), show='headings')
        self.comments_tree.heading('status', text='Status')
        self.comments_tree.heading('comment', text='Comment')
        self.comments_tree.heading('id', text='ID')
        self.comments_tree.column('status', width=100, anchor=tk.W)
        self.comments_tree.column('comment', width=600, anchor=tk.W)
        self.comments_tree.column('id', width=200, anchor=tk.W)
        
        scroll_y = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.comments_tree.yview)
        self.comments_tree.configure(yscrollcommand=scroll_y.set)
        
        self.comments_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        # Status Bar
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.progress = ttk.Progressbar(self.status_bar, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.status_text = ttk.Label(self.status_bar, text="Ready")
        self.status_text.pack(side=tk.RIGHT, padx=5)

    def check_saved_token(self):
        if self.auth.load_token():
            self.manager = YouTubeManager(self.auth.youtube)
            self.update_auth_status("Logged in via saved token")

    def update_auth_status(self, message):
        self.auth_status.config(text=f"Status: {message}")
        self.login_btn.state(['disabled' if self.auth.is_authenticated() else '!disabled'])

    def start_login(self):
        self.start_operation("Authenticating...")
        threading.Thread(target=self.perform_login).start()

    def perform_login(self):
        try:
            self.auth.authenticate()
            self.manager = YouTubeManager(self.auth.youtube)
            self.update_auth_status("Login successful")
        except Exception as e:
            messagebox.showerror("Login Failed", str(e))
        finally:
            self.end_operation()

    def fetch_videos(self):
        channel_input = self.channel_entry.get().strip()
        channel_id = helpers.extract_channel_id(channel_input)
        
        if not channel_id:
            messagebox.showerror("Invalid Input", "Please enter a valid Channel ID or URL")
            return

        self.start_operation("Fetching videos...")
        threading.Thread(target=self.load_videos, args=(channel_id,)).start()

    def load_videos(self, channel_id):
        try:
            self.video_list = self.manager.fetch_videos(channel_id)
            self.root.after(0, self.populate_video_combo)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Fetch Error", str(e)))
        finally:
            self.root.after(0, self.end_operation)

    def populate_video_combo(self):
        self.video_combo['values'] = [f"{v[0]} ({v[1]})" for v in self.video_list]
        if self.video_list:
            self.video_combo.current(0)
            self.current_video_id = self.video_list[0][1]

    def on_video_select(self, event):
        idx = self.video_combo.current()
        self.current_video_id = self.video_list[idx][1]

    def scan_comments(self):
        if not self.current_video_id:
            messagebox.showwarning("No Video", "Please select a video first")
            return

        self.start_operation("Scanning comments...")
        threading.Thread(target=self.load_comments).start()

    def load_comments(self):
        try:
            self.comment_data = self.manager.fetch_comments(self.current_video_id)
            self.root.after(0, self.populate_comments)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
        finally:
            self.root.after(0, self.end_operation)

    def populate_comments(self):
        self.comments_tree.delete(*self.comments_tree.get_children())
        for cid, text, display_text in self.comment_data:
            self.comments_tree.insert('', 'end', values=('Pending', display_text, cid))

    def detect_spam(self):
        self.start_operation("Detecting spam...")
        threading.Thread(target=self.run_spam_detection).start()

    def run_spam_detection(self):
        try:
            spam_indices = self.detector.detect_spam(self.comment_data)
            self.root.after(0, lambda: self.highlight_spam(spam_indices))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Detection Error", str(e)))
        finally:
            self.root.after(0, self.end_operation)

    def highlight_spam(self, spam_indices):
        for idx in spam_indices:
            self.comments_tree.set(self.comments_tree.get_children()[idx], 'status', 'SPAM')
            self.comments_tree.item(self.comments_tree.get_children()[idx], tags=('spam',))
        
        self.comments_tree.tag_configure('spam', background='#ffe6e6')

    def delete_selected(self):
        selected = self.comments_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select comments to delete")
            return

        comment_ids = [self.comments_tree.item(i, 'values')[2] for i in selected]
        self.start_operation("Deleting comments...")
        threading.Thread(target=self.perform_deletion, args=(comment_ids,)).start()

    def perform_deletion(self, comment_ids):
        try:
            self.manager.delete_comments(comment_ids)
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Deleted {len(comment_ids)} comments"))
            self.root.after(0, self.scan_comments)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Deletion Error", str(e)))
        finally:
            self.root.after(0, self.end_operation)

    def start_operation(self, message):
        self.progress.start()
        self.status_text.config(text=message)
        self.set_widget_state('disabled')

    def end_operation(self):
        self.progress.stop()
        self.status_text.config(text="Ready")
        self.set_widget_state('!disabled')

    def set_widget_state(self, state):
        widgets = [self.channel_entry, self.fetch_btn, self.video_combo,
                   self.scan_btn, self.detect_btn, self.delete_btn]
        for widget in widgets:
            widget.state([state])