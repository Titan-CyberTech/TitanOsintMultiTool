import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font
import socket
import whois
import requests
import re
import json
from datetime import datetime
from bs4 import BeautifulSoup
import threading
import webbrowser
from PIL import Image, ImageTk
import os
import sys

class OSINTMultiTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Titan MultiTools OSINT")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        self.root.resizable(True, True)
        
        # Définir des variables de couleur
        self.bg_color = "#2b2b2b"
        self.accent_color = "#4CAF50"
        self.text_color = "#f0f0f0"
        self.highlight_color = "#66bb6a"
        self.secondary_bg = "#3b3b3b"
        
        # Configurer le thème de base
        self.root.config(bg=self.bg_color)
        
        # Polices
        self.title_font = font.Font(family="Helvetica", size=14, weight="bold")
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
                             focuscolor=self.highlight_color)
        
        self.style.map("TButton",
                       background=[('active', self.highlight_color), ('pressed', self.highlight_color)],
                       relief=[('pressed', 'sunken'), ('!pressed', 'raised')])
        
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
                             foreground=self.accent_color, 
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
                            arrowcolor=self.accent_color)
        
        self.style.map("TCombobox",
                      fieldbackground=[('readonly', self.secondary_bg)],
                      background=[('readonly', self.secondary_bg)],
                      foreground=[('readonly', self.text_color)])
        
        self.style.configure("TLabelframe", 
                             background=self.bg_color, 
                             foreground=self.text_color)
        
        self.style.configure("TLabelframe.Label", 
                             background=self.bg_color, 
                             foreground=self.accent_color,
                             font=self.header_font)
        
        # Icon and logo
        try:
            # Create a resources directory if it doesn't exist
            if not os.path.exists("resources"):
                os.makedirs("resources")
                
            # Create a simple OSINTMultiTool logo text as a placeholder
            self.logo_text = "OSINT\nMultiTool"
            
            # Créer un logo temporaire (si nous n'avons pas de fichier logo)
            self.logo_canvas = tk.Canvas(root, width=60, height=60, bg=self.accent_color, highlightthickness=0)
            self.logo_canvas.create_text(30, 30, text=self.logo_text, fill=self.text_color, font=self.header_font, justify=tk.CENTER)
        except Exception as e:
            print(f"Error loading logo: {e}")
        
        # Main container
        self.container = ttk.Frame(root)
        self.container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header area with logo
        self.header_frame = ttk.Frame(self.container)
        self.header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Place logo
        try:
            self.logo_canvas.pack(side=tk.LEFT, padx=10)
        except:
            pass
        
        # App title
        self.title_label = ttk.Label(self.header_frame, text="Titan OSINT MultiTool", style="Title.TLabel")
        self.title_label.pack(side=tk.LEFT, padx=10)
        
        # About button
        self.about_button = ttk.Button(self.header_frame, text="À propos", command=self.show_about)
        self.about_button.pack(side=tk.RIGHT, padx=10)
        
        # Main frame
        self.main_frame = ttk.Frame(self.container)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Input area
        self.input_frame = ttk.Frame(self.main_frame, style="Card.TFrame")
        self.input_frame.pack(fill=tk.X, pady=10, padx=5, ipady=10)
        
        # Inner padding frame
        self.input_inner = ttk.Frame(self.input_frame)
        self.input_inner.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(self.input_inner, text="Cible (domaine/IP/email) :", style="Header.TLabel").pack(side=tk.LEFT, padx=5)
        self.target_entry = ttk.Entry(self.input_inner, width=50, font=self.normal_font)
        self.target_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Tool selection
        self.tool_frame = ttk.Frame(self.main_frame, style="Card.TFrame")
        self.tool_frame.pack(fill=tk.X, pady=10, padx=5, ipady=10)
        
        # Inner padding frame
        self.tool_inner = ttk.Frame(self.tool_frame)
        self.tool_inner.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(self.tool_inner, text="Sélectionner un outil :", style="Header.TLabel").pack(side=tk.LEFT, padx=5)
        
        self.tool_choice = tk.StringVar()
        self.tool_dropdown = ttk.Combobox(self.tool_inner, textvariable=self.tool_choice, state="readonly", width=25, font=self.normal_font)
        self.tool_dropdown["values"] = (
            "DNS Lookup", 
            "Whois Lookup", 
            "IP Geolocation", 
            "Email Validator", 
            "HTTP Headers", 
            "Port Scanner",
            "Métadonnées Site Web"
        )
        self.tool_dropdown.current(0)
        self.tool_dropdown.pack(side=tk.LEFT, padx=5)
        
        # Action button
        self.analyze_button = ttk.Button(self.tool_inner, text="Analyser", command=self.start_analysis)
        self.analyze_button.pack(side=tk.LEFT, padx=10)
        
        self.clear_button = ttk.Button(self.tool_inner, text="Effacer", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Results area
        self.results_frame = ttk.LabelFrame(self.main_frame, text="Résultats")
        self.results_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=5)
        
        # Configure the text widget with custom colors
        self.results_text = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.results_text.config(
            font=self.mono_font,
            background=self.secondary_bg,
            foreground=self.text_color,
            insertbackground=self.text_color,  # cursor color
            selectbackground=self.accent_color,
            selectforeground=self.text_color,
            borderwidth=0,
            highlightthickness=0
        )
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Prêt")
        self.status_bar = ttk.Label(self.container, textvariable=self.status_var, style="Status.TLabel", anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Bind keyboard shortcuts
        self.root.bind('<Control-q>', lambda e: self.root.destroy())
        self.root.bind('<F1>', lambda e: self.show_about())
        self.root.bind('<Return>', lambda e: self.start_analysis())
        self.root.bind('<Escape>', lambda e: self.clear_results())
        
        # Center the window on startup
        self.center_window()
        
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
        about_window.title("À propos de Titan OSINT MultiTool")
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
        ttk.Label(frame, text="Titan OSINT MultiTool", font=self.title_font, foreground=self.accent_color, background=self.bg_color).pack(pady=(0,10))
        
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
        
    def start_analysis(self):
        """Démarre l'analyse dans un thread séparé pour éviter de bloquer l'interface"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Erreur", "Veuillez entrer une cible")
            return
            
        self.status_var.set("Analyse en cours...")
        self.analyze_button.config(state="disabled")
        
        # Démarrer l'analyse dans un thread séparé
        threading.Thread(target=self.perform_analysis, args=(target,), daemon=True).start()
    
    def perform_analysis(self, target):
        """Effectue l'analyse en fonction de l'outil sélectionné"""
        tool = self.tool_choice.get()
        
        try:
            if tool == "DNS Lookup":
                result = self.dns_lookup(target)
            elif tool == "Whois Lookup":
                result = self.whois_lookup(target)
            elif tool == "IP Geolocation":
                result = self.ip_geolocation(target)
            elif tool == "Email Validator":
                result = self.email_validator(target)
            elif tool == "HTTP Headers":
                result = self.http_headers(target)
            elif tool == "Port Scanner":
                result = self.port_scanner(target)
            elif tool == "Métadonnées Site Web":
                result = self.website_metadata(target)
            else:
                result = "Outil non reconnu"
                
            self.update_results(result)
            self.status_var.set("Analyse terminée")
        except Exception as e:
            self.update_results(f"Erreur lors de l'analyse: {str(e)}")
            self.status_var.set("Erreur")
        
        # Réactiver le bouton d'analyse
        self.root.after(0, lambda: self.analyze_button.config(state="normal"))
    
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
            
            # Formater les informations WHOIS de manière lisible
            for key, value in w.items():
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
            except:
                result += f"{port}\t{service}\tErreur\n"
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
            title = soup.title.string if soup.title else "Non disponible"
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

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = OSINTMultiTool(root)
        root.mainloop()
    except Exception as e:
        print(f"Erreur critique: {str(e)}")