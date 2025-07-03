import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font, filedialog
import socket
import whois
import requests
import re
import json
import time
import hashlib
import ipaddress
import ssl
import urllib.parse
from datetime import datetime
from bs4 import BeautifulSoup
import threading
import webbrowser
from PIL import Image, ImageTk
import os
import sys
import csv
import io
import random
import platform
from concurrent.futures import ThreadPoolExecutor

class TitanOSINTMultiTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Titan OSINT MultiTool")
        self.root.geometry("1000x750")
        self.root.minsize(900, 650)
        self.root.resizable(True, True)
        
        # Définir des variables de couleur
        self.bg_color = "#1a1a2e"  # Bleu très foncé
        self.accent_color = "#0f3460"  # Bleu intense
        self.highlight_color = "#e94560"  # Rouge accentué
        self.text_color = "#f0f0f0"  # Blanc cassé
        self.secondary_bg = "#16213e"  # Bleu foncé
        self.success_color = "#4CAF50"  # Vert
        self.warning_color = "#FF9800"  # Orange
        self.error_color = "#F44336"  # Rouge
        
        # Version de l'application
        self.app_version = "1.1"
        
        # Configurer le thème de base
        self.root.config(bg=self.bg_color)
        
        # Polices
        self.title_font = font.Font(family="Helvetica", size=16, weight="bold")
        self.header_font = font.Font(family="Helvetica", size=12, weight="bold")
        self.normal_font = font.Font(family="Helvetica", size=10)
        self.mono_font = font.Font(family="Consolas", size=10)
        
        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Utiliser un thème moderne
        
        self.style.configure("TFrame", background=self.bg_color)
        self.style.configure("Card.TFrame", background=self.secondary_bg, relief="raised")
        
        self.style.configure("TButton", 
                             background=self.accent_color, 
                             foreground=self.text_color, 
                             font=self.normal_font,
                             borderwidth=0,
                             focusthickness=3,
                             focuscolor=self.highlight_color,
                             padding=8,
                             relief="flat"
        )
        self.style.map("TButton",
            background=[('active', self.highlight_color), ('pressed', self.highlight_color)],
            relief=[('pressed', 'groove'), ('!pressed', 'flat')]
        )
        
        self.style.configure("Success.TButton",
                             background=self.success_color,
                             foreground=self.text_color)
        
        self.style.configure("Warning.TButton",
                             background=self.warning_color,
                             foreground=self.text_color)
        
        self.style.configure("Error.TButton",
                             background=self.error_color,
                             foreground=self.text_color)
        
        self.style.configure("TLabel", 
                             background=self.bg_color, 
                             foreground=self.text_color, 
                             font=self.normal_font)
        
        self.style.configure("Header.TLabel", 
                             background=self.bg_color, 
                             foreground=self.text_color, 
                             font=self.header_font)
        
        self.style.configure("Title.TLabel", 
                             background=self.bg_color, 
                             foreground=self.highlight_color, 
                             font=self.title_font)
        
        self.style.configure("Status.TLabel", 
                             background=self.secondary_bg, 
                             foreground=self.text_color, 
                             font=self.normal_font,
                             relief="sunken")
        
        self.style.configure("TCombobox", 
                            background=self.secondary_bg,
                            fieldbackground=self.secondary_bg,
                            foreground=self.text_color,
                            arrowcolor=self.highlight_color)
        
        self.style.map("TCombobox",
                      fieldbackground=[('readonly', self.secondary_bg)],
                      background=[('readonly', self.secondary_bg)],
                      foreground=[('readonly', self.text_color)])
        
        self.style.configure("TLabelframe", 
                             background=self.bg_color, 
                             foreground=self.text_color)
        
        self.style.configure("TLabelframe.Label", 
                             background=self.bg_color, 
                             foreground=self.highlight_color,
                             font=self.header_font)
                             
        # Styles personnalisés
        self.style.configure("Card.TLabelframe", background=self.secondary_bg, foreground=self.text_color, borderwidth=2, relief="groove")
        self.style.configure("Card.TLabelframe.Label", background=self.secondary_bg, foreground=self.highlight_color, font=self.header_font)
        
        # Variables globales
        self.current_scan_results = {}  # Pour stocker les résultats de scan
        self.stop_scan = False  # Pour arrêter un scan en cours
        self.target_history = []  # Pour stocker l'historique des cibles
        
        # Main container
        self.container = ttk.Frame(root)
        self.container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Menu bar
        self.menu_bar = tk.Menu(root)
        self.root.config(menu=self.menu_bar)
        
        # File menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0, bg=self.secondary_bg, fg=self.text_color)
        self.file_menu.add_command(label="Nouveau scan", command=self.clear_results)
        self.file_menu.add_command(label="Exporter résultats", command=self.export_results)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Quitter", command=self.root.destroy)
        self.menu_bar.add_cascade(label="Fichier", menu=self.file_menu)
        
        # Tools menu
        self.tools_menu = tk.Menu(self.menu_bar, tearoff=0, bg=self.secondary_bg, fg=self.text_color)
        self.tools_menu.add_command(label="Analyse rapide", command=lambda: self.quick_scan())
        self.tools_menu.add_command(label="Multi-scan", command=lambda: self.multi_scan())
        self.tools_menu.add_separator()
        self.tools_menu.add_command(label="Options avancées", command=self.show_advanced_options)
        self.menu_bar.add_cascade(label="Outils", menu=self.tools_menu)
        
        # About menu
        self.about_menu = tk.Menu(self.menu_bar, tearoff=0, bg=self.secondary_bg, fg=self.text_color)
        self.about_menu.add_command(label="À propos", command=self.show_about)
        self.about_menu.add_command(label="Documentation", command=lambda: webbrowser.open("https://github.com/titan-osint/docs"))
        self.menu_bar.add_cascade(label="Aide", menu=self.about_menu)
        
        # Main tabs
        self.tab_control = ttk.Notebook(self.container)
        self.tab_control.pack(fill=tk.BOTH, expand=True)
        
        # Scan tab
        self.scan_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.scan_tab, text="Scanner")
        
        # Reports tab
        self.reports_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.reports_tab, text="Rapports")
        
        # Setup tabs content
        self.setup_scan_tab()
        self.setup_reports_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Prêt")
        self.status_bar = ttk.Label(self.container, textvariable=self.status_var, style="Status.TLabel", anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Bind keyboard shortcuts
        self.root.bind('<Control-q>', lambda e: self.root.destroy())
        self.root.bind('<F1>', lambda e: self.show_about())
        self.root.bind('<F5>', lambda e: self.start_analysis())
        self.root.bind('<Escape>', lambda e: self.stop_current_scan())
        self.root.bind('<Control-s>', lambda e: self.export_results())
        
        # Center the window on startup
        self.center_window()
        
        # Ajoute dans __init__ après la création des boutons :
        for btn in [self.analyze_button, self.stop_button, self.clear_button, self.export_button]:
            btn.bind("<Enter>", lambda e, b=btn: b.config(style="Hover.TButton"))
            btn.bind("<Leave>", lambda e, b=btn: b.config(style="TButton"))

        self.style.configure("Hover.TButton", background="#e94560", foreground=self.text_color)
        
    def setup_scan_tab(self):
        """Configure l'onglet Scanner"""
        # Input area
        self.input_frame = ttk.Labelframe(self.scan_tab, text="Entrée", style="Card.TLabelframe")
        self.input_frame.pack(fill=tk.X, pady=10, padx=5, ipady=10)
        
        # Inner padding frame
        self.input_inner = ttk.Frame(self.input_frame)
        self.input_inner.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(self.input_inner, text="Cible (domaine/IP/email) :", style="Header.TLabel").pack(side=tk.LEFT, padx=5)
        
        # Target entry with history
        self.target_var = tk.StringVar()
        self.target_combo = ttk.Combobox(self.input_inner, textvariable=self.target_var, font=self.normal_font)
        self.target_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Tool selection
        self.tool_frame = ttk.Labelframe(self.scan_tab, text="Outil", style="Card.TLabelframe")
        self.tool_frame.pack(fill=tk.X, pady=10, padx=5, ipady=10)
        
        # Inner padding frame
        self.tool_inner = ttk.Frame(self.tool_frame)
        self.tool_inner.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(self.tool_inner, text="Sélectionner un outil :", style="Header.TLabel").pack(side=tk.LEFT, padx=5)
        
        self.tool_choice = tk.StringVar()
        self.tool_dropdown = ttk.Combobox(self.tool_inner, textvariable=self.tool_choice, state="readonly", width=30, font=self.normal_font)
        self.tool_dropdown["values"] = (
            "DNS Lookup Avancé", 
            "Whois Lookup Détaillé", 
            "IP Geolocation Plus", 
            "Email Validator Pro", 
            "HTTP Headers Analyzer", 
            "Port Scanner Avancé",
            "Website Intelligence",
            "SSL Certificate Analyzer",
            "Domain Reputation Check",
            "Digital Footprint Scanner",
            "Content Analysis"
        )
        self.tool_dropdown.current(0)
        self.tool_dropdown.pack(side=tk.LEFT, padx=5)
        
        # Action buttons frame
        self.action_frame = ttk.Frame(self.tool_inner)
        self.action_frame.pack(side=tk.LEFT, padx=10)
        
        # Action buttons
        self.analyze_button = ttk.Button(self.action_frame, text="Analyser", style="TButton", command=self.start_analysis)
        self.analyze_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(self.action_frame, text="Arrêter", style="Error.TButton", command=self.stop_current_scan)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.stop_button.config(state="disabled")
        
        self.clear_button = ttk.Button(self.action_frame, text="Effacer", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        self.export_button = ttk.Button(self.action_frame, text="Exporter", command=self.export_results)
        self.export_button.pack(side=tk.LEFT, padx=5)
        
        # Options frame
        self.options_frame = ttk.LabelFrame(self.scan_tab, text="Options d'analyse")
        self.options_frame.pack(fill=tk.X, pady=5, padx=5)
        
        # Options inner frame
        self.options_inner = ttk.Frame(self.options_frame)
        self.options_inner.pack(fill=tk.X, padx=10, pady=10)
        
        # Timeout option
        ttk.Label(self.options_inner, text="Timeout (s):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.timeout_var = tk.IntVar(value=10)
        self.timeout_spinbox = ttk.Spinbox(self.options_inner, from_=1, to=60, textvariable=self.timeout_var, width=5)
        self.timeout_spinbox.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Depth option
        ttk.Label(self.options_inner, text="Profondeur:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.depth_var = tk.IntVar(value=1)
        self.depth_spinbox = ttk.Spinbox(self.options_inner, from_=1, to=3, textvariable=self.depth_var, width=5)
        self.depth_spinbox.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        
        # Threads option
        ttk.Label(self.options_inner, text="Threads:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        self.threads_var = tk.IntVar(value=10)
        self.threads_spinbox = ttk.Spinbox(self.options_inner, from_=1, to=50, textvariable=self.threads_var, width=5)
        self.threads_spinbox.grid(row=0, column=5, padx=5, pady=5, sticky=tk.W)
        
        # Verbose option
        self.verbose_var = tk.BooleanVar(value=True)
        self.verbose_check = ttk.Checkbutton(self.options_inner, text="Mode détaillé", variable=self.verbose_var)
        self.verbose_check.grid(row=0, column=6, padx=5, pady=5, sticky=tk.W)
        
        # Save history option
        self.save_history_var = tk.BooleanVar(value=True)
        self.save_history_check = ttk.Checkbutton(self.options_inner, text="Sauvegarder l'historique", variable=self.save_history_var)
        self.save_history_check.grid(row=0, column=7, padx=5, pady=5, sticky=tk.W)
        
        # Results area with notebook
        self.results_notebook = ttk.Notebook(self.scan_tab)
        self.results_notebook.pack(fill=tk.BOTH, expand=True, pady=5, padx=5)
        
        # Results tab
        self.results_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.results_tab, text="Résultats")
        
        # Raw data tab
        self.raw_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.raw_tab, text="Données brutes")
        
        # Summary tab
        self.summary_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.summary_tab, text="Résumé")
        
        # Results textbox
        self.results_text = scrolledtext.ScrolledText(self.results_tab, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.results_text.config(
            font=("Consolas", 12),
            background="#23234a",
            foreground=self.text_color,
            insertbackground=self.text_color,
            selectbackground=self.highlight_color,
            selectforeground=self.text_color,
            borderwidth=0,
            highlightthickness=0
        )
        
        # Raw data textbox
        self.raw_text = scrolledtext.ScrolledText(self.raw_tab, wrap=tk.WORD)
        self.raw_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.raw_text.config(
            font=self.mono_font,
            background=self.secondary_bg,
            foreground=self.text_color,
            insertbackground=self.text_color,
            selectbackground=self.highlight_color,
            selectforeground=self.text_color,
            borderwidth=0,
            highlightthickness=0
        )
        
        # Summary frame
        self.summary_frame = ttk.Frame(self.summary_tab)
        self.summary_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Summary tree view
        columns = ("Propriété", "Valeur")
        self.summary_tree = ttk.Treeview(self.summary_frame, columns=columns, show="headings")
        self.summary_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        
        # Configure columns
        self.summary_tree.heading("Propriété", text="Propriété")
        self.summary_tree.heading("Valeur", text="Valeur")
        self.summary_tree.column("Propriété", width=200, anchor=tk.W)
        self.summary_tree.column("Valeur", width=400, anchor=tk.W)
        
        # Add scrollbar to the treeview
        scrollbar = ttk.Scrollbar(self.summary_frame, orient="vertical", command=self.summary_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.summary_tree.configure(yscrollcommand=scrollbar.set)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(self.scan_tab, variable=self.progress_var, maximum=100)
        self.progress.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Separator(self.scan_tab, orient='horizontal').pack(fill=tk.X, padx=5, pady=5)
        
    def setup_reports_tab(self):
        """Configure l'onglet Rapports"""
        # Reports frame
        self.reports_frame = ttk.Frame(self.reports_tab)
        self.reports_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # History label
        ttk.Label(self.reports_frame, text="Historique des analyses", style="Header.TLabel").pack(anchor=tk.W, pady=(0, 10))
        
        # Treeview for history
        columns = ("Date", "Cible", "Type", "Résultat")
        self.history_tree = ttk.Treeview(self.reports_frame, columns=columns, show="headings")
        self.history_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        
        # Configure columns
        self.history_tree.heading("Date", text="Date")
        self.history_tree.heading("Cible", text="Cible")
        self.history_tree.heading("Type", text="Type d'analyse")
        self.history_tree.heading("Résultat", text="Résultat")
        
        self.history_tree.column("Date", width=150, anchor=tk.W)
        self.history_tree.column("Cible", width=200, anchor=tk.W)
        self.history_tree.column("Type", width=200, anchor=tk.W)
        self.history_tree.column("Résultat", width=200, anchor=tk.W)
        
        # Add scrollbar to the treeview
        scrollbar = ttk.Scrollbar(self.reports_frame, orient="vertical", command=self.history_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        # Bind select event
        self.history_tree.bind("<<TreeviewSelect>>", self.on_history_select)
        
    def center_window(self):
        """Centre la fenêtre sur l'écran"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    
    def show_about(self):
        """Affiche une boîte de dialogue 'À propos'"""
        about_window = tk.Toplevel(self.root)
        about_window.title("À propos d'OSINT MultiTool")
        about_window.geometry("400x300")
        about_window.config(bg=self.bg_color)
        about_window.resizable(False, False)
        
        # Make it modal
        about_window.transient(self.root)
        about_window.grab_set()
        
        # Center it
        about_window.update_idletasks()
        width = about_window.winfo_width()
        height = about_window.winfo_height()
        x = (about_window.winfo_screenwidth() // 2) - (width // 2)
        y = (about_window.winfo_screenheight() // 2) - (height // 2)
        about_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        
        # About content
        frame = ttk.Frame(about_window)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        ttk.Label(frame, text="OSINT MultiTool", font=self.title_font, foreground=self.accent_color, background=self.bg_color).pack(pady=(0,10))
        
        # Version
        ttk.Label(frame, text="Version 1.0", font=self.normal_font, foreground=self.text_color, background=self.bg_color).pack(pady=(0,20))
        
        # Description
        desc = "Un outil OSINT multifonctions simple pour effectuer des analyses de base sur des domaines, adresses IP et emails."
        desc_label = ttk.Label(frame, text=desc, font=self.normal_font, foreground=self.text_color, background=self.bg_color, wraplength=350, justify=tk.CENTER)
        desc_label.pack(pady=(0,20))
        
        # Copyright
        ttk.Label(frame, text="© 2025", font=self.normal_font, foreground=self.text_color, background=self.bg_color).pack(pady=(0,10))
        
        # Close button
        ttk.Button(frame, text="Fermer", command=about_window.destroy).pack(pady=10)
        
    def show_advanced_options(self):
        """Affiche une boîte de dialogue pour les options avancées (placeholder)"""
        messagebox.showinfo("Options avancées", "Les options avancées seront bientôt disponibles.")
    
    def start_analysis(self):
        """Démarre l'analyse dans un thread séparé pour éviter de bloquer l'interface"""
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Erreur", "Veuillez entrer une cible")
            return

        self.status_var.set("Analyse en cours...")
        self.analyze_button.config(state="disabled")
        self.stop_button.config(state="normal")  # <-- Active le bouton Arrêter

        # Démarrer l'analyse dans un thread séparé
        threading.Thread(target=self.perform_analysis, args=(target,), daemon=True).start()
    
    def perform_analysis(self, target):
        """Effectue l'analyse en fonction de l'outil sélectionné"""
        tool = self.tool_choice.get()
        
        try:
            if tool == "DNS Lookup Avancé":
                result = self.dns_lookup(target)
            elif tool == "Whois Lookup Détaillé":
                result = self.whois_lookup(target)
            elif tool == "IP Geolocation Plus":
                result = self.ip_geolocation(target)
            elif tool == "Email Validator Pro":
                result = self.email_validator(target)
            elif tool == "HTTP Headers Analyzer":
                result = self.http_headers(target)
            elif tool == "Port Scanner Avancé":
                result = self.port_scanner(target)
            elif tool == "Website Intelligence":
                result = self.website_metadata(target)
            elif tool == "SSL Certificate Analyzer":
                result = self.ssl_certificate_analyzer(target)
            elif tool == "Domain Reputation Check":
                result = self.domain_reputation_check(target)
            elif tool == "Digital Footprint Scanner":
                result = self.digital_footprint_scanner(target)
            elif tool == "Content Analysis":
                result = self.content_analysis(target)
            else:
                result = "Outil non reconnu"
                
            self.update_results(result)
            self.status_var.set("Analyse terminée")
        except Exception as e:
            self.update_results(f"Erreur lors de l'analyse: {str(e)}")
            self.status_var.set("Erreur")
        
        # Réactiver le bouton d'analyse
        self.root.after(0, lambda: self.analyze_button.config(state="normal"))
        self.root.after(0, lambda: self.stop_button.config(state="disabled"))  # <-- Désactive le bouton Arrêter
    
    def update_results(self, text):
        """Met à jour la zone de résultats de manière thread-safe"""
        def _update():
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, text)
        self.root.after(0, _update)
    
    def clear_results(self):
        """Efface la zone de résultats"""
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Prêt")
    
    def export_results(self):
        """Exporte les résultats actuels dans un fichier texte"""
        results = self.results_text.get(1.0, tk.END).strip()
        if not results:
            messagebox.showinfo("Exporter", "Aucun résultat à exporter.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(results)
                messagebox.showinfo("Exporter", f"Résultats exportés dans {file_path}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de l'export: {str(e)}")
    
    def dns_lookup(self, domain):
        """Effectue une recherche DNS"""
        try:
            result = f"DNS Lookup pour {domain}:\n\n"
            
            # Adresse IP
            ip = socket.gethostbyname(domain)
            result += f"Adresse IP: {ip}\n\n"
            
            # Essai de résolution inverse
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                result += f"Nom d'hôte: {hostname}\n\n"
            except socket.herror:
                result += "Résolution inverse: Non disponible\n\n"
            
            return result
        except socket.gaierror:
            return f"Erreur: Impossible de résoudre {domain}"
    
    def whois_lookup(self, domain):
        """Effectue une recherche WHOIS"""
        try:
            w = whois.whois(domain)
            result = f"WHOIS pour {domain}:\n\n"
            if isinstance(w, dict):
                items = w.items()
            else:
                items = w.__dict__.items()
            for key, value in items:
                if value and key not in ["status", "raw"]:
                    if isinstance(value, list):
                        value = ", ".join(str(v) for v in value)
                    result += f"{key}: {value}\n"
            return result
        except Exception as e:
            return f"Erreur WHOIS: {str(e)}"
    
    def ip_geolocation(self, ip):
        """Obtient des informations de géolocalisation pour une adresse IP"""
        # Vérifier si l'entrée est un domaine et le convertir en IP
        if not self.is_valid_ip(ip):
            try:
                ip = socket.gethostbyname(ip)
            except socket.gaierror:
                return f"Erreur: {ip} n'est pas une adresse IP ou un domaine valide."
        
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            
            if data["status"] == "success":
                result = f"Géolocalisation IP pour {ip}:\n\n"
                result += f"Pays: {data.get('country', 'N/A')}\n"
                result += f"Région: {data.get('regionName', 'N/A')}\n"
                result += f"Ville: {data.get('city', 'N/A')}\n"
                result += f"FAI: {data.get('isp', 'N/A')}\n"
                result += f"Organisation: {data.get('org', 'N/A')}\n"
                result += f"Latitude: {data.get('lat', 'N/A')}\n"
                result += f"Longitude: {data.get('lon', 'N/A')}\n"
                result += f"Fuseau horaire: {data.get('timezone', 'N/A')}\n"
                return result
            else:
                return f"Erreur: Impossible d'obtenir des informations pour {ip}"
        except Exception as e:
            return f"Erreur de géolocalisation: {str(e)}"
    
    def is_valid_ip(self, ip):
        """Vérifie si la chaîne est une adresse IP valide"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        octets = ip.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False
        return True
    
    def email_validator(self, email):
        """Valide une adresse e-mail et collecte des informations sur le domaine"""
        # Vérification simple du format d'e-mail
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return f"Erreur: {email} n'est pas une adresse e-mail valide."
        
        domain = email.split('@')[1]
        
        result = f"Validation d'e-mail pour {email}:\n\n"
        result += f"Format: Valide\n"
        
        # Vérifier si le domaine existe
        try:
            socket.gethostbyname(domain)
            result += f"Domaine: Existe\n\n"
            
            # Vérifier les enregistrements MX
            try:
                mx_records = socket.getaddrinfo(domain, 25, 0, socket.SOCK_STREAM)
                result += f"Serveurs de messagerie: Trouvés\n"
                result += f"Cette adresse e-mail pourrait être valide.\n"
            except socket.gaierror:
                result += f"Serveurs de messagerie: Non trouvés\n"
                result += f"Cette adresse e-mail pourrait ne pas être valide.\n"
                
        except socket.gaierror:
            result += f"Domaine: N'existe pas\n"
            result += f"Cette adresse e-mail n'est pas valide.\n"
        
        return result
    
    def http_headers(self, url):
        """Récupère les en-têtes HTTP d'une URL"""
        if not url.startswith('http'):
            url = 'http://' + url
            
        try:
            response = requests.head(url, allow_redirects=True, timeout=5)
            
            # Essayer avec HTTPS si HTTP échoue
            if response.status_code >= 400 and not url.startswith('https'):
                url = 'https://' + url.lstrip('http://')
                response = requests.head(url, allow_redirects=True, timeout=5)
            
            result = f"En-têtes HTTP pour {url}:\n\n"
            result += f"Code de statut: {response.status_code}\n\n"
            
            for header, value in response.headers.items():
                result += f"{header}: {value}\n"
            
            return result
        except requests.exceptions.RequestException as e:
            return f"Erreur lors de la récupération des en-têtes: {str(e)}"
    
    def port_scanner(self, host):
        """Scanner les ports les plus courants"""
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP Proxy"
        }
        
        # Convertir le domaine en IP si nécessaire
        if not self.is_valid_ip(host):
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                return f"Erreur: Impossible de résoudre l'hôte {host}"
        else:
            ip = host
        
        result = f"Scanner de ports pour {host} ({ip}):\n\n"
        result += "Port\tService\tStatut\n"
        result += "-" * 40 + "\n"
        
        open_ports = 0
        
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                conn = sock.connect_ex((ip, port))
                if conn == 0:
                    result += f"{port}\t{service}\tOuvert\n"
                    open_ports += 1
                else:
                    result += f"{port}\t{service}\tFermé\n"
            except Exception as e:
                result += f"{port}\t{service}\tErreur: {str(e)}\n"
            finally:
                sock.close()
        
        result += f"\nRésumé: {open_ports} port(s) ouvert(s) sur {len(common_ports)} testés."
        return result
    
    def website_metadata(self, url):
        """Extrait les métadonnées d'un site web"""
        if not url.startswith('http'):
            url = 'http://' + url
            
        try:
            response = requests.get(url, timeout=10)
            
            # Essayer avec HTTPS si HTTP échoue
            if response.status_code >= 400 and not url.startswith('https'):
                url = 'https://' + url.lstrip('http://')
                response = requests.get(url, timeout=10)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            result = f"Métadonnées pour {url}:\n\n"
            
            # Titre
            title = soup.title.string.strip() if soup.title and soup.title.string else "Non disponible"
            result += f"Titre: {title}\n\n"
            
            # Métadonnées
            result += "Balises Meta:\n"
            meta_tags = soup.find_all('meta')
            if meta_tags:
                for tag in meta_tags:
                    name = tag.get('name') or tag.get('property') or "unknown"
                    content = tag.get('content', 'N/A')
                    result += f"- {name}: {content}\n"
            else:
                result += "Aucune balise meta trouvée\n"
            
            # Liens externes
            result += "\nLiens externes:\n"
            external_links = set()
            domain = url.split('/')[2]
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('http') and domain not in href:
                    external_links.add(href)
            
            if external_links:
                for i, link in enumerate(list(external_links)[:10], 1):
                    result += f"{i}. {link}\n"
                if len(external_links) > 10:
                    result += f"... et {len(external_links) - 10} autres liens\n"
            else:
                result += "Aucun lien externe trouvé\n"
            
            # JavaScript
            result += "\nScripts JavaScript:\n"
            scripts = soup.find_all('script', src=True)
            if scripts:
                for i, script in enumerate(scripts[:5], 1):
                    result += f"{i}. {script['src']}\n"
                if len(scripts) > 5:
                    result += f"... et {len(scripts) - 5} autres scripts\n"
            else:
                result += "Aucun script externe trouvé\n"
            
            return result
        except Exception as e:
            return f"Erreur lors de l'extraction des métadonnées: {str(e)}"
    
    def ssl_certificate_analyzer(self, target):
        """Analyse le certificat SSL d'un domaine"""
        import ssl
        import socket

        # Nettoyage de l'URL pour ne garder que le domaine
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        port = 443

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            
            result = f"Certificat SSL pour {domain}:\n\n"
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            result += f"Sujet: {subject.get('commonName', 'N/A')}\n"
            result += f"Issuer: {issuer.get('commonName', 'N/A')}\n"
            result += f"Organisation: {subject.get('organizationName', 'N/A')}\n"
            result += f"Valide du: {cert.get('notBefore', 'N/A')}\n"
            result += f"Valide jusqu'au: {cert.get('notAfter', 'N/A')}\n"
            result += f"Numéro de série: {cert.get('serialNumber', 'N/A')}\n"
            result += f"Algorithme de signature: {cert.get('signatureAlgorithm', 'N/A') if 'signatureAlgorithm' in cert else 'N/A'}\n"
            result += f"Extensions:\n"
            for ext in cert.get('subjectAltName', []):
                if ext[0] == 'DNS':
                    result += f"  - {ext[1]}\n"
            return result
        except Exception as e:
            return f"Erreur lors de l'analyse SSL: {str(e)}"
    
    def domain_reputation_check(self, target):
        """Vérifie la réputation d'un domaine via des services publics"""
        # Nettoyage du domaine
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        result = f"Vérification de réputation pour {domain} :\n\n"
        result += "- [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search?url={domain})\n"
        result += "- [VirusTotal](https://www.virustotal.com/gui/domain/{domain}/detection)\n"
        result += "- [urlscan.io](https://urlscan.io/domain/{domain})\n"
        result += "- [Talos Intelligence](https://talosintelligence.com/reputation_center/lookup?search={domain})\n"
        result += "- [AbuseIPDB](https://www.abuseipdb.com/check/{domain})\n"
        result += "\nOuvre ces liens dans ton navigateur pour voir la réputation du domaine sur chaque service."

        return result

    def digital_footprint_scanner(self, target):
        """Recherche la présence du domaine/email sur quelques plateformes publiques"""
        import requests

        # Détermine si c'est un email ou un domaine
        if "@" in target:
            username = target.split("@")[0]
            domain = target.split("@")[1]
        else:
            username = None
            domain = target

        result = f"Empreinte numérique pour {target} :\n\n"

        # Recherche Google (simple lien)
        result += f"- Google : https://www.google.com/search?q={target}\n"

        # LinkedIn
        result += f"- LinkedIn : https://www.linkedin.com/search/results/all/?keywords={target}\n"

        # Twitter
        if username:
            result += f"- Twitter : https://twitter.com/{username}\n"
        else:
            result += f"- Twitter : https://twitter.com/search?q={domain}\n"

        # Facebook
        result += f"- Facebook : https://www.facebook.com/search/top/?q={target}\n"

        # GitHub
        if username:
            result += f"- GitHub : https://github.com/{username}\n"
        else:
            result += f"- GitHub : https://github.com/search?q={domain}\n"

        # Vérification de présence (optionnel, ici juste des liens)
        result += "\n(Ouverture manuelle recommandée pour vérifier la présence réelle sur chaque plateforme.)"

        return result
    
    def content_analysis(self, target):
        """Analyse le contenu d'une page web : stats, mots fréquents, liens, images"""
        if not target.startswith('http'):
            url = 'http://' + target
        else:
            url = target

        try:
            response = requests.get(url, timeout=10)
            if response.status_code >= 400 and not url.startswith('https'):
                url = 'https://' + target.lstrip('http://')
                response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)
            words = re.findall(r'\w+', text.lower())
            word_count = len(words)
            char_count = len(text)
            unique_words = len(set(words))

            # Mots les plus fréquents
            from collections import Counter
            most_common = Counter(words).most_common(10)

            # Liens et images
            links = [a['href'] for a in soup.find_all('a', href=True)]
            images = [img['src'] for img in soup.find_all('img', src=True)]

            result = f"Analyse de contenu pour {url} :\n\n"
            result += f"Nombre de mots : {word_count}\n"
            result += f"Nombre de caractères : {char_count}\n"
            result += f"Mots uniques : {unique_words}\n"
            result += "\nMots les plus fréquents :\n"
            for word, count in most_common:
                result += f"  - {word} : {count}\n"
            result += f"\nNombre de liens : {len(links)}\n"
            result += f"Nombre d'images : {len(images)}\n"
            if links:
                result += "\nQuelques liens :\n"
                for l in links[:5]:
                    result += f"  - {l}\n"
            if images:
                result += "\nQuelques images :\n"
                for img in images[:5]:
                    result += f"  - {img}\n"
            return result
        except Exception as e:
            return f"Erreur lors de l'analyse de contenu : {str(e)}"
    
    def stop_current_scan(self):
        """Demande l'arrêt du scan en cours"""
        self.stop_scan = True
        self.status_var.set("Scan arrêté par l'utilisateur.")
        self.analyze_button.config(state="normal")
    
    def on_history_select(self, event):
        """Affiche les détails du rapport sélectionné dans la zone de résultats"""
        selected_item = self.history_tree.selection()
        if selected_item:
            values = self.history_tree.item(selected_item[0], "values")
            # Affiche les détails dans la zone de résultats
            details = (
                f"Date : {values[0]}\n"
                f"Cible : {values[1]}\n"
                f"Type d'analyse : {values[2]}\n"
                f"Résultat : {values[3]}"
            )
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, details)

    def draw_gradient(self, canvas, color1, color2):
        """Dessine un dégradé horizontal sur un canvas"""
        width = int(canvas['width'])
        height = int(canvas['height'])
        r1, g1, b1 = self.root.winfo_rgb(color1)
        r2, g2, b2 = self.root.winfo_rgb(color2)
        r_ratio = float(r2 - r1) / width
        g_ratio = float(g2 - g1) / width
        b_ratio = float(b2 - b1) / width
        for i in range(width):
            nr = int(r1 + (r_ratio * i))
            ng = int(g1 + (g_ratio * i))
            nb = int(b1 + (b_ratio * i))
            color = f'#{nr//256:02x}{ng//256:02x}{nb//256:02x}'
            canvas.create_line(i, 0, i, height, fill=color)

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = TitanOSINTMultiTool(root)
        root.mainloop()
    except Exception as e:
        print(f"Erreur critique: {str(e)}")