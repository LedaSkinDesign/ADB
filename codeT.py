import sys # Importa sys per controllare sys.frozen
import subprocess
import socket
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import os
import json # json e datetime sembrano non usati nel codice fornito, ma li mantengo
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor # Aggiunto per una scansione più veloce
import requests
import webbrowser

# --- Definizione dei percorsi ---
# Assumo che scrcpy.exe, scrcpy-server.jar e la cartella 'adb' siano tutti nella directory dello script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Se l'applicazione è impacchettata (es. con PyInstaller --onefile)
# sys.executable è il percorso dell'eseguibile, non dello script Python
if getattr(sys, 'frozen', False):
    SCRIPT_DIR = os.path.dirname(sys.executable)
    print(f"Esecuzione da eseguibile impacchettato. Percorsi relativi a: {SCRIPT_DIR}")
else:
     print(f"Esecuzione da script. Percorsi relativi a: {SCRIPT_DIR}")

ADB_DIR = os.path.join(SCRIPT_DIR, "ADB") # La cartella che contiene adb.exe
ADB_PATH = os.path.join(ADB_DIR, "adb.exe")
SCRCPY_DIR = os.path.join(ADB_DIR, "scrcpy") # Cartella scrcpy
SCRCPY_PATH = os.path.join(SCRCPY_DIR, "scrcpy.exe")
SCRCPY_SERVER_PATH = os.path.join(SCRCPY_DIR, "scrcpy-server.jar")
HEXNODE_APK_URL = "https://downloads.hexnode.com/HexnodeMDM.apk"

print(f"ADB_PATH: {ADB_PATH}")
print(f"SCRCPY_PATH: {SCRCPY_PATH}")
print(f"SCRCPY_SERVER_PATH: {SCRCPY_SERVER_PATH}")


# --- Funzione di aiuto per eseguire comandi ADB ---
def run_adb_command(args, device_id=None, timeout=30): # Aumentato timeout default a 30s
    """Esegue un comando ADB e ritorna stdout/stderr. Gestisce gli errori."""
    command = [ADB_PATH]
    if device_id:
        command.extend(["-s", device_id])
    command.extend(args)

    try:
        # Usa CREATE_NO_WINDOW per evitare il popup della console su Windows
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0

        print(f"Esecuzione comando ADB: {' '.join(subprocess.list2cmdline(command))}") # Stampa il comando eseguito per debug

        result = subprocess.run(command,
                              capture_output=True,
                              text=True, # Decodifica l'output come testo (utf-8 di default)
                              creationflags=creationflags,
                              timeout=timeout) # Aggiunge un timeout
        return result.stdout, result.stderr
    except FileNotFoundError:
        return "", f"Errore: Comando ADB non trovato a {ADB_PATH}\n"
    except subprocess.TimeoutExpired:
        return "", f"Errore: Comando ADB '{subprocess.list2cmdline(command)}' scaduto (timeout {timeout}s).\n"
    except Exception as e:
        return "", f"Errore nell'esecuzione del comando ADB '{subprocess.list2cmdline(command)}': {str(e)}\n"


# --- Scanner di Rete che usa ThreadPoolExecutor ---
class NetworkScanner(threading.Thread):
    def __init__(self, network, device_found_callback, progress_callback, scan_complete_callback):
        super().__init__()
        self.network_range = network
        self._device_found_callback = device_found_callback # Callback per dispositivo trovato (thread-safe)
        self._progress_callback = progress_callback       # Callback per aggiornamento progresso (thread-safe)
        self._scan_complete_callback = scan_complete_callback # Callback per completamento scansione (thread-safe)
        self._running = True
        self.daemon = True # Consente al thread di uscire con il programma principale
        self._executor = ThreadPoolExecutor(max_workers=100) # Aumentato il numero di worker per scansione più veloce
        self._futures = []

    def run(self):
        try:
            # Consente indirizzi IP host nella definizione di rete (es. 192.168.1.1/24 è valido)
            network = ipaddress.ip_network(self.network_range, strict=False)
            ip_list = list(network.hosts())
            total_ips = len(ip_list)
            processed_ips = 0
            lock = threading.Lock() # Per aggiornamenti thread-safe di processed_ips

            def check_ip(ip):
                """Controlla se un IP:5555 è aperto."""
                if not self._running: return None # Ferma se la scansione è stata interrotta
                try:
                    sock = socket.create_connection((str(ip), 5555), timeout=0.1) # Timeout leggermente aumentato
                    sock.close()
                    return f"{ip}:5555"
                except (socket.timeout, ConnectionRefusedError, OSError):
                    return None # Non aperto o errore di connessione
                except Exception as e:
                    print(f"Errore imprevisto durante il check di {ip}: {e}") # Stampa errori inattesi nel check
                    return None

            def on_task_complete(future):
                """Callback per quando un task check_ip finisce."""
                nonlocal processed_ips
                if not self._running: return # Ferma se la scansione è stata interrotta

                try:
                    result = future.result() # Ottiene il risultato (IP:porta o None)
                    if result:
                        # Pianifica la callback sul thread principale di Tkinter
                        self._device_found_callback(result)
                except Exception as e:
                     print(f"Errore nella gestione risultato future: {e}") # Gestisce errori nel callback future

                with lock:
                    processed_ips += 1
                    progress = int((processed_ips / total_ips) * 100)
                    # Pianifica l'aggiornamento del progresso sul thread principale di Tkinter
                    self._progress_callback(progress)

            # Invia i task al thread pool
            self._futures = [self._executor.submit(check_ip, ip) for ip in ip_list]

            # Aggiunge le callback per i risultati
            for future in self._futures:
                future.add_done_callback(on_task_complete)

            # Non è strettamente necessario attendere qui, ma il thread esce
            # quando l'executor si spegne o viene interrotto.
            # L'importante è che le callback aggiornino la GUI tramite after().

        except Exception as e:
            print(f"Errore durante la scansione: {str(e)}") # Stampa errori della scansione principale
            # Potresti aggiungere un segnale/callback di errore qui se necessario
        finally:
            if self._running: # Esegue solo se la scansione non è stata interrotta
                # Pianifica la callback di completamento scansione sul thread principale di Tkinter
                self._scan_complete_callback()


    def stop(self):
        """Segnala allo scanner di fermarsi."""
        print("Richiesta interruzione scanner...")
        self._running = False
        # Tenta di cancellare i future - potrebbe non funzionare se i task sono già in esecuzione
        for future in self._futures:
            future.cancel()
        # Spegne l'executor - wait=False impedisce di bloccare il metodo stop
        self._executor.shutdown(wait=False)
        print("Scanner segnalato per interruzione.")


# --- Frame Informazioni Dispositivo ---
class DeviceInfoFrame(ttk.LabelFrame):
    def __init__(self, parent, device_id):
        super().__init__(parent, text=f"Info Dispositivo: {device_id}")
        self.device_id = device_id
        self.grid_columnconfigure(1, weight=1) # Consente alla colonna delle informazioni di espandersi

        self._is_updating = False # Flag per prevenire aggiornamenti multipli concorrenti
        self._update_scheduled = False # Flag per pianificare un aggiornamento se occupato

        # Dizionario per memorizzare le StringVar (che aggiornano le etichette)
        self.labels = {}

        # Crea le righe per le informazioni
        self.add_info_row("Serial Number", 0)
        self.add_info_row("Model", 1)
        self.add_info_row("Android Version", 2)
        self.add_info_row("Manufacturer", 3)
        self.add_info_row("Device", 4)
        self.add_info_row("Product", 5)
        self.add_info_row("Battery Level", 6)
        self.add_info_row("Last Update", 7)

        # Pianifica un aggiornamento iniziale, non bloccante
        self.after(100, self.update_info)


    def add_info_row(self, label_text, row):
        ttk.Label(self, text=f"{label_text}:").grid(row=row, column=0, sticky='w', padx=5, pady=2)
        # Usa textvariable per aggiornamenti più semplici e thread-safe (tramite self.after)
        var = tk.StringVar(value="Fetching...") # Valore iniziale mentre carica
        value_label = ttk.Label(self, textvariable=var)
        value_label.grid(row=row, column=1, sticky='w', padx=5, pady=2)
        self.labels[label_text] = var # Memorizza la StringVar

    def update_info(self):
        """Recupera e aggiorna le informazioni del dispositivo in un thread separato."""
        if self._is_updating:
            self._update_scheduled = True # Pianifica un altro aggiornamento più tardi
            return

        self._is_updating = True
        self._update_scheduled = False

        # Imposta lo stato iniziale "Fetching..." sulle etichette (opzionale)
        # for key, var in self.labels.items():
        #      if key != "Serial Number":
        #           var.set("Fetching...")

        def fetch_data():
            """Funzione worker per recuperare i dati in un thread."""
            try:
                props = {
                    "Serial Number": self.device_id, # Seriale è già noto
                    "Model": run_adb_command(["shell", "getprop", "ro.product.model"], self.device_id)[0].strip(),
                    "Android Version": run_adb_command(["shell", "getprop", "ro.build.version.release"], self.device_id)[0].strip(),
                    "Manufacturer": run_adb_command(["shell", "getprop", "ro.product.manufacturer"], self.device_id)[0].strip(),
                    "Device": run_adb_command(["shell", "getprop", "ro.product.device"], self.device_id)[0].strip(),
                    "Product": run_adb_command(["shell", "getprop", "ro.product.name"], self.device_id)[0].strip(),
                    "Battery Level": self.get_battery_level(),
                    "Last Update": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                # Sostituisci output vuoti con "N/A"
                for key, value in props.items():
                    if isinstance(value, str) and not value:
                        props[key] = "N/A"

            except Exception as e:
                 print(f"Errore nel recuperare le info per {self.device_id}: {e}")
                 props = None # Indica fallimento

            # Pianifica l'aggiornamento della GUI sul thread principale
            self.after(0, update_gui, props)

        def update_gui(props):
            """Aggiorna le etichette della GUI sul thread principale."""
            if props:
                for key, var in self.labels.items():
                    # Assicura che la chiave esista in props prima di accedervi
                    var.set(str(props.get(key, "N/A"))) # Usa .get con default "N/A"
            else:
                # Gestisce il caso in cui il recupero dei dati è fallito
                for key, var in self.labels.items():
                    if key != "Serial Number": # Mantieni il Serial Number se noto
                        var.set("Errore nel recupero info")


            self._is_updating = False
            if self._update_scheduled:
                self.after(100, self.update_info) # Esegui l'aggiornamento pianificato


        # Avvia il thread worker
        threading.Thread(target=fetch_data, daemon=True).start()


    def get_battery_level(self):
        """Recupera il livello della batteria usando adb shell dumpsys."""
        try:
            stdout, stderr = run_adb_command(["shell", "dumpsys", "battery"], self.device_id)
            if stderr and "Exception" in stderr: # Controlla specifici errori in stderr
                print(f"Errore in dumpsys battery per {self.device_id}:\n{stderr}")
                return "N/A (Errore ADB)"
            for line in stdout.splitlines():
                if "level:" in line:
                    # Estrai il numero dopo "level:"
                    parts = line.split("level:")
                    if len(parts) > 1:
                        level_str = parts[1].strip()
                        if level_str.isdigit():
                             return f"{level_str}%"
            return "N/A" # Non trovato o formato inatteso
        except Exception as e:
            print(f"Errore generico nel recuperare la batteria per {self.device_id}: {e}")
            return "N/A (Errore)"


# --- Applicazione GUI Principale ---
class ADBGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LEDA ADB Manager")
        self.geometry("1200x800")
        self.minsize(900, 600)

        # Applica tema moderno
        style = ttk.Style(self)
        try:
            style.theme_use('vista')
        except:
            style.theme_use('clam')
        style.configure('.', font=('Segoe UI', 11))
        style.configure('TButton', padding=8, relief='flat', font=('Segoe UI', 11), borderwidth=0)
        style.configure('TLabel', font=('Segoe UI', 11))
        style.configure('TEntry', font=('Segoe UI', 11))
        style.configure('Treeview.Heading', font=('Segoe UI', 11, 'bold'))
        style.map('TButton', background=[('active', '#e5e5e5')])

        self.configure(bg='#f3f3f3')

        self.scanner = None
        self._scanning = False
        self.device_frames = {}
        self._refresh_timer = None
        self.device_vars = {}
        self.selected_devices = set()
        self.lock_selection = False

        if not self.check_required_files():
            self.after(10, self.destroy)
            return

        # Main container
        self.main_container = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Left panel
        left_panel = ttk.Frame(self.main_container)
        self.main_container.add(left_panel, weight=1)

        # Device control frame (pulsanti rapidi)
        control_top = ttk.Frame(left_panel)
        control_top.pack(fill=tk.X, padx=0, pady=4)
        ttk.Button(control_top, text="Seleziona tutti", command=self.select_all_devices).pack(side=tk.LEFT, padx=4)
        ttk.Button(control_top, text="Deseleziona tutti", command=self.deselect_all_devices).pack(side=tk.LEFT, padx=4)
        self.lock_btn = ttk.Button(control_top, text="Blocca selezione", command=self.toggle_lock_selection)
        self.lock_btn.pack(side=tk.LEFT, padx=4)
        ttk.Button(control_top, text="Terminale ADB", command=self.open_adb_terminal_popup).pack(side=tk.LEFT, padx=4)

        # Device list with checkboxes and table
        self.device_frame = ttk.LabelFrame(left_panel, text="Dispositivi")
        self.device_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=8)

        columns = ("Seleziona", "ID", "Modello", "Versione", "Stato", "IP")
        self.device_tree = ttk.Treeview(self.device_frame, columns=columns, show="headings")
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=120 if col!="Seleziona" else 80, anchor=tk.CENTER, stretch=True)
        self.device_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.device_tree.bind('<Button-1>', self.on_treeview_click)

        # Manual IP connection frame
        ip_frame = ttk.LabelFrame(left_panel, text="Connessione Manuale IP")
        ip_frame.pack(fill=tk.X, padx=0, pady=8)
        self.ip_entry = ttk.Entry(ip_frame)
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6, pady=8)
        ttk.Button(ip_frame, text="Connetti", command=self.connect_ip_manual).pack(side=tk.RIGHT, padx=6, pady=8)

        # Control buttons
        control_frame = ttk.Frame(left_panel)
        control_frame.pack(fill=tk.X, padx=0, pady=8)
        ttk.Button(control_frame, text="Scansiona Rete", command=self.start_network_scan).pack(fill=tk.X, pady=4)
        ttk.Button(control_frame, text="Connetti Scrcpy", command=self.run_scrcpy).pack(fill=tk.X, pady=4)
        ttk.Button(control_frame, text="Disconnetti Dispositivo", command=self.disconnect_device).pack(fill=tk.X, pady=4)
        ttk.Button(control_frame, text="Scarica HexnodeMDM", command=self.download_hexnode).pack(fill=tk.X, pady=4)
        ttk.Button(control_frame, text="Installa APK", command=self.install_apk).pack(fill=tk.X, pady=4)

        # Right panel (Terminal and Device Info)
        right_panel = ttk.Frame(self.main_container)
        self.main_container.add(right_panel, weight=2)
        info_frame = ttk.LabelFrame(right_panel, text="Informazioni Dispositivi")
        info_frame.pack(fill=tk.X, padx=0, pady=8)
        self.terminal = ADBTerminal(right_panel)
        self.terminal.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        self.check_adb_server()
        self._schedule_refresh()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def check_required_files(self):
        """Controlla se i file adb e scrcpy esistono nei percorsi attesi."""
        missing_files = []
        # Controlla prima che la cartella adb esista
        if not os.path.isdir(ADB_DIR):
            missing_files.append(f"cartella '{os.path.basename(ADB_DIR)}'")
        # Controlla i file specifici
        if not os.path.exists(ADB_PATH):
            missing_files.append(f"file '{os.path.join(os.path.basename(ADB_DIR), os.path.basename(ADB_PATH))}'")
        if not os.path.exists(SCRCPY_PATH):
            missing_files.append(f"file '{os.path.basename(SCRCPY_PATH)}'")
        if not os.path.exists(SCRCPY_SERVER_PATH):
            missing_files.append(f"file '{os.path.basename(SCRCPY_SERVER_PATH)}'")


        if missing_files:
            error_msg = f"ATTENZIONE:\nNon ho trovato i seguenti file/directory necessari nella cartella:\n'{SCRIPT_DIR}'\n"
            error_msg += "\n- " + "\n- ".join(missing_files)
            error_msg += "\n\nAssicurati di aver scaricato l'intero pacchetto Scrcpy e di aver estratto i file qui."
            messagebox.showerror("Errore File Mancanti", error_msg)
            return False
        return True

    def check_adb_server(self):
        """Avvia/controlla il server ADB."""
        print("Avvio/Verifica server ADB...")
        stdout, stderr = run_adb_command(["start-server"], timeout=10) # Timeout breve per l'avvio
        if stderr and "adb server version" not in stderr: # "adb server version" a volte è in stderr con successo
            print(f"ADB start-server stderr (potrebbe essere normale):\n{stderr}") # Stampa stderr per debugging
            # Decidi se mostrare un avviso a seconda della severità degli errori
            # if "error:" in stderr.lower():
            #      messagebox.warning("Avviso ADB", f"Errore o avviso nell'avvio del server ADB:\n{stderr}")
        else:
             print("Server ADB avviato/verificato.") # Stampa nella console

    def _schedule_refresh(self):
        """Pianifica il prossimo refresh."""
        # Annulla ogni refresh in sospeso
        if self._refresh_timer:
            self.after_cancel(self._refresh_timer)
        # Pianifica un nuovo refresh solo se non stiamo scansionando
        if not self._scanning:
            self._refresh_timer = self.after(5000, self.refresh_devices)

    def get_selected_devices(self):
        """Restituisce una lista di ID dispositivo per gli elementi selezionati."""
        # Usa self.selected_devices per la selezione persistente
        return list(self.selected_devices)

    def start_network_scan(self):
        """Avvia la scansione della rete per dispositivi Android."""
        if self._scanning:
            return
            
        self._scanning = True
        network = "192.168.1.0/24"
        
        def scan():
            try:
                network_obj = ipaddress.ip_network(network)
                self.terminal.output.insert(tk.END, f"Avvio scansione rete {network} sulla porta 5555...\n")
                devices_found = False
                
                for ip in network_obj.hosts():
                    if not self._scanning:
                        break
                        
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.1)
                        result = sock.connect_ex((str(ip), 5555))
                        if result == 0:
                            device = f"{ip}:5555"
                            self.after(0, lambda d=device: self._process_discovered_device(d))
                            devices_found = True
                        sock.close()
                    except:
                        continue
                        
            except Exception as e:
                self.terminal.output.insert(tk.END, f"Errore durante la scansione: {str(e)}\n")
            finally:
                self._scanning = False
                self.terminal.output.insert(tk.END, "Scansione completata.\n")
                self.refresh_devices()
                if devices_found:
                    messagebox.showinfo("Scansione Completata", "Dispositivi trovati. Seleziona i dispositivi e usa 'Connetti Scrcpy' per avviare la connessione remota.")
                return
                
        threading.Thread(target=scan, daemon=True).start()

    def add_discovered_device_threadsafe(self, ip_port):
        """Aggiunge in modo sicuro un dispositivo scoperto al processo del thread principale."""
        self.after(0, self._process_discovered_device, ip_port) # Pianifica sul thread principale

    def _process_discovered_device(self, ip_port):
        """Connette a un dispositivo scoperto se non è già nella lista."""
        # Controlla se il dispositivo è già nella tabella
        for item in self.device_tree.get_children():
            values = self.device_tree.item(item, 'values')
            if values and str(values[1]).startswith(ip_port):
                print(f"Dispositivo {ip_port} già listato. Ignoro connessione automatica.")
                return  # Già nella lista

        print(f"Dispositivo trovato: {ip_port}. Tentativo connessione automatica...")
        stdout, stderr = run_adb_command(["connect", ip_port])
        print(f"ADB connect {ip_port} output:\n{stdout}\n{stderr}")
        if "connected" in stdout.lower() or "already connected" in stdout.lower():
            print(f"Connesso o già connesso a {ip_port}.")
            self.refresh_devices()
        else:
            print(f"Impossibile connettersi automaticamente a {ip_port}. Output:\n{stdout}\n{stderr}")


    def update_progress_threadsafe(self, value):
        """Aggiorna in modo sicuro la barra di progresso da un thread."""
        # Tkinter DoubleVar è generalmente thread-safe per set()
        self.terminal.terminal_output.insert(tk.END, f"Aggiornamento progress bar: {value}%\n")


    def scan_completed_threadsafe(self):
        """Gestisce in modo sicuro il completamento della scansione sul thread principale."""
        self.after(0, self._process_scan_complete) # Pianifica sul thread principale

    def _process_scan_complete(self):
        """Chiamata quando la scansione di rete finisce."""
        self._scanning = False
        print("Scansione completata.")
        self.terminal.terminal_output.insert(tk.END, "Scansione completata.\n")
        self.refresh_devices() # Aggiorna la lista dopo la scansione


    def refresh_devices(self):
        """Aggiorna la tabella dei dispositivi con checkbox persistenti."""
        stdout, stderr = run_adb_command(["devices", "-l"])
        self.device_tree.delete(*self.device_tree.get_children())
        self.device_vars.clear()
        if stdout:
            for line in stdout.splitlines():
                if line.strip() and not line.startswith("List"):
                    device_id = line.split()[0]
                    status = line.split()[1] if len(line.split()) > 1 else "unknown"
                    model = self.get_device_property(device_id, "ro.product.model")
                    version = self.get_device_property(device_id, "ro.build.version.release")
                    ip = device_id if ":" in device_id else ""
                    # Checkbox persistente
                    var = tk.BooleanVar(value=(device_id in self.selected_devices))
                    def on_check(dev_id=device_id, v=var):
                        if self.lock_selection:
                            v.set(True)
                            return
                        if v.get():
                            self.selected_devices.add(dev_id)
                        else:
                            self.selected_devices.discard(dev_id)
                    var.trace_add('write', lambda *args, dev_id=device_id, v=var: on_check(dev_id, v))
                    self.device_vars[device_id] = var
                    # Inserisci la riga con checkbox (testo "✔" se selezionato, vuoto se no)
                    checkmark = "✔" if var.get() else ""
                    self.device_tree.insert("", tk.END, values=(checkmark, device_id, model, version, status, ip), tags=(device_id,))
        # Aggiorna visualizzazione checkmark
        self.update_tree_checkmarks()
        self._schedule_refresh()

    def update_tree_checkmarks(self):
        """Aggiorna la colonna checkbox della tabella in base a self.device_vars."""
        for item in self.device_tree.get_children():
            device_id = self.device_tree.item(item, 'values')[1]
            var = self.device_vars.get(device_id)
            checkmark = "✔" if var and var.get() else ""
            vals = list(self.device_tree.item(item, 'values'))
            vals[0] = checkmark
            self.device_tree.item(item, values=vals)

    def select_all_devices(self):
        for device_id, var in self.device_vars.items():
            var.set(True)
        self.selected_devices = set(self.device_vars.keys())
        self.update_tree_checkmarks()

    def deselect_all_devices(self):
        if self.lock_selection:
            return
        for device_id, var in self.device_vars.items():
            var.set(False)
        self.selected_devices.clear()
        self.update_tree_checkmarks()

    def toggle_lock_selection(self):
        self.lock_selection = not self.lock_selection
        if self.lock_selection:
            self.lock_btn.config(text="Sblocca selezione")
        else:
            self.lock_btn.config(text="Blocca selezione")

    def get_device_property(self, device_id, property_name):
        """Recupera una proprietà del dispositivo."""
        stdout, stderr = run_adb_command(["shell", "getprop", property_name], device_id)
        return stdout.strip() if stdout else "N/A"

    def disconnect_device(self):
        """Disconnette il dispositivo/i selezionato/i."""
        selected_device_ids = self.get_selected_devices()
        
        if not selected_device_ids:
            messagebox.showwarning("Avviso", "Seleziona almeno un dispositivo.")
            return
            
        for device_id in selected_device_ids:
            try:
                # Disconnetti scrcpy
                if os.name == 'nt':  # Windows
                    subprocess.run(['taskkill', '/F', '/IM', 'scrcpy.exe'], 
                                 creationflags=subprocess.CREATE_NO_WINDOW)
                else:  # Linux/Mac
                    subprocess.run(['pkill', '-f', f'scrcpy.*{device_id}'])
                
                # Disconnetti il dispositivo da ADB
                run_adb_command(["disconnect", device_id])
                
                self.terminal.output.insert(tk.END, f"Dispositivo {device_id} disconnesso\n")
            except Exception as e:
                self.terminal.output.insert(tk.END, f"Errore nel disconnettere {device_id}: {str(e)}\n")
        
        self.refresh_devices()  # Aggiorna la lista dei dispositivi

    def run_scrcpy(self):
        """Avvia scrcpy per il dispositivo/i selezionato/i."""
        selected_device_ids = self.get_selected_devices()

        if not selected_device_ids:
            messagebox.showwarning("Avviso", "Seleziona almeno un dispositivo dalla lista.")
            return

        if not os.path.exists(SCRCPY_PATH):
            messagebox.showerror("Errore", f"Scrcpy.exe non trovato in:\n{SCRCPY_PATH}")
            return
        if not os.path.exists(SCRCPY_SERVER_PATH):
            messagebox.showerror("Errore", f"Scrcpy-server.jar non trovato in:\n{SCRCPY_SERVER_PATH}")
            return

        for device_id in selected_device_ids:
            try:
                # Verifica connessione
                self.terminal.output.insert(tk.END, f"Verifico connessione a {device_id}...\n")
                stdout, stderr = run_adb_command(["connect", device_id])
                self.terminal.output.insert(tk.END, f"Risultato connessione: {stdout}\n")
                
                if "connected" not in stdout.lower() and "already connected" not in stdout.lower():
                    self.terminal.output.insert(tk.END, f"Impossibile connettersi a {device_id}\n")
                    continue

                # Verifica che il dispositivo sia effettivamente connesso
                stdout, stderr = run_adb_command(["devices"])
                if device_id not in stdout:
                    self.terminal.output.insert(tk.END, f"Dispositivo {device_id} non presente nella lista dei dispositivi connessi\n")
                    continue

                # Ferma eventuali istanze di scrcpy in esecuzione
                self.terminal.output.insert(tk.END, "Fermo eventuali istanze di scrcpy in esecuzione...\n")
                if os.name == 'nt':  # Windows
                    subprocess.run(['taskkill', '/F', '/IM', 'scrcpy.exe'], 
                                 creationflags=subprocess.CREATE_NO_WINDOW)
                else:  # Linux/Mac
                    subprocess.run(['pkill', '-f', 'scrcpy'])

                # Imposta la variabile d'ambiente per il server scrcpy
                env = os.environ.copy()
                env['SCRCPY_SERVER_PATH'] = SCRCPY_SERVER_PATH

                # Comando scrcpy corretto (senza --no-audio)
                command = [
                    SCRCPY_PATH,
                    "-s", device_id,
                    "--max-size", "1280",
                    "--bit-rate", "2M"
                ]

                self.terminal.output.insert(tk.END, f"Avvio scrcpy con comando: {' '.join(command)}\n")
                
                # Esegui scrcpy
                creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                process = subprocess.Popen(command, 
                                        creationflags=creationflags,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        env=env)
                
                # Verifica se scrcpy si è avviato correttamente
                try:
                    stdout, stderr = process.communicate(timeout=2)
                    if stderr:
                        error_msg = stderr.decode()
                        self.terminal.output.insert(tk.END, f"Errore scrcpy: {error_msg}\n")
                        raise Exception(f"Errore scrcpy: {error_msg}")
                except subprocess.TimeoutExpired:
                    # Se non riceviamo errori entro 2 secondi, probabilmente è partito correttamente
                    self.terminal.output.insert(tk.END, f"Scrcpy avviato per {device_id}\n")
                except Exception as e:
                    messagebox.showerror("Errore", f"Errore nell'avvio di scrcpy su {device_id}: {str(e)}")
                    process.kill()

            except Exception as e:
                messagebox.showerror("Errore", f"Errore nell'avvio di scrcpy su {device_id}: {str(e)}")
                self.terminal.output.insert(tk.END, f"Errore dettagliato: {str(e)}\n")

    def reboot_device(self):
        """Riavvia il dispositivo/i selezionato/i."""
        selected_device_ids = self.get_selected_devices()

        if not selected_device_ids:
            messagebox.showwarning("Avviso", "Seleziona almeno un dispositivo.")
            return

        confirm = messagebox.askyesno("Conferma Riavvio",
                                       f"Sei sicuro di voler riavviare {len(selected_device_ids)} dispositivo/i?")

        if confirm:
            for device_id in selected_device_ids:
                print(f"Riavvio di {device_id}...")
                stdout, stderr = run_adb_command(["reboot"], device_id=device_id, timeout=10) # Timeout breve, il comando ADB torna subito
                print(f"ADB reboot {device_id} output:\n{stdout}\n{stderr}")
                if stderr and "error" in stderr.lower():
                     messagebox.showerror("Errore Riavvio", f"Errore nel riavvio di {device_id}:\n{stderr}")
                else:
                    # Il comando adb reboot solitamente invia il comando e non attende il completamento
                    print(f"Comando di riavvio inviato a {device_id}")
            # I dispositivi spariranno dalla lista mentre si riavviano
            self.after(2000, self.refresh_devices) # Pianifica un refresh dopo un breve ritardo

    def connect_ip_manual(self):
        """Tenta manualmente di connettersi a un indirizzo IP."""
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Avviso", "Inserisci un indirizzo IP valido.")
            return

        if ":" not in ip:
            ip = f"{ip}:5555" # Porta ADB di default

        print(f"Tentativo connessione manuale a {ip}...")
        stdout, stderr = run_adb_command(["connect", ip])
        print(f"ADB connect {ip} output:\n{stdout}\n{stderr}")
        
        if "connected" in stdout.lower():
            messagebox.showinfo("Successo", f"Connesso con successo a {ip}")
            self.refresh_devices()  # Aggiorna la lista dei dispositivi
        elif "already connected" in stdout.lower():
            messagebox.showinfo("Informazione", f"Dispositivo {ip} è già connesso.")
            self.refresh_devices()  # Aggiorna la lista dei dispositivi
        else:
            messagebox.showwarning("Errore Connessione", f"Impossibile connettersi a {ip}.\nOutput ADB:\n{stdout}\n{stderr}")
            # Prova a riavviare il server ADB e riprovare
            print("Tentativo di riavvio del server ADB...")
            run_adb_command(["kill-server"])
            run_adb_command(["start-server"])
            stdout, stderr = run_adb_command(["connect", ip])
            if "connected" in stdout.lower():
                messagebox.showinfo("Successo", f"Connesso con successo a {ip} dopo riavvio server ADB")
                self.refresh_devices()
            else:
                messagebox.showwarning("Errore Connessione", 
                    f"Impossibile connettersi a {ip} anche dopo riavvio server ADB.\n"
                    f"Verifica che:\n"
                    f"1. Il dispositivo sia acceso e sbloccato\n"
                    f"2. Il debug USB sia abilitato\n"
                    f"3. La porta 5555 sia aperta\n"
                    f"4. Il dispositivo sia sulla stessa rete\n"
                    f"Output ADB:\n{stdout}\n{stderr}")

    def install_apk(self):
        """Apre la finestra di dialogo file e installa l'APK selezionato sui dispositivi selezionati."""
        selected_device_ids = self.get_selected_devices()

        if not selected_device_ids:
            messagebox.showwarning("Avviso", "Seleziona almeno un dispositivo.")
            return

        apk_file = filedialog.askopenfilename(
            title="Seleziona File APK da Installare",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")]
        )

        if not apk_file:
            print("Selezione APK per installazione annullata.")
            return

        for device_id in selected_device_ids:
            print(f"Installazione APK '{os.path.basename(apk_file)}' su {device_id}...")
            # Usa -r per sostituire l'applicazione esistente
            stdout, stderr = run_adb_command(["install", "-r", apk_file], device_id=device_id, timeout=240) # Aumentato timeout a 4 minuti

            print(f"Risultato installazione APK su {device_id}:\nStdout:\n{stdout}\nStderr:\n{stderr}")

            if "Success" in stdout:
                print(f"APK installato con successo su {device_id}")
                # Potresti mostrare una messagebox per ogni dispositivo o una riassuntiva alla fine
                messagebox.showinfo("Successo Installazione", f"APK installato con successo su {device_id}")
            else:
                print(f"Errore durante l'installazione dell'APK su {device_id}:\n{stderr or stdout}")
                messagebox.warning("Errore Installazione", f"Errore durante l'installazione dell'APK su {device_id}.\nOutput:\n{stderr or stdout}") # Mostra stderr prima se c'è

    def download_hexnode(self):
        """Scarica l'APK HexnodeMDM."""
        try:
            response = requests.get(HEXNODE_APK_URL, stream=True)
            response.raise_for_status()
            
            apk_path = os.path.join(SCRIPT_DIR, "HexnodeMDM.apk")
            with open(apk_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        
            messagebox.showinfo("Successo", "APK HexnodeMDM scaricato con successo")
        except Exception as e:
            messagebox.showerror("Errore", f"Errore nel download dell'APK: {str(e)}")

    # --- Pulizia alla chiusura ---
    def on_closing(self):
        """Gestisce l'evento di chiusura finestra per fermare thread e timer."""
        print("Chiusura applicazione...")
        # Annulla il timer di refresh
        if self._refresh_timer:
            self.after_cancel(self._refresh_timer)
            print("Refresh timer fermato.")

        # Ferma lo scanner se in esecuzione
        if self._scanning and self.scanner and self.scanner.is_alive():
            print("Interruzione thread scanner...")
            self.scanner.stop()
            # Dà al thread un momento per fermarsi, ma non bloccare troppo a lungo
            self.scanner.join(timeout=2.0)
            if self.scanner.is_alive():
                 print("Il thread scanner non si è fermato correttamente.") # Debugging

        # Spegni i thread pool usati da NetworkScanner (se presenti)
        if hasattr(self, 'scanner') and self.scanner and hasattr(self.scanner, '_executor') and self.scanner._executor:
             print("Spegnimento executor scanner...")
             try:
                 # wait=True attende il completamento dei task rimanenti (importante per i task in corso)
                 self.scanner._executor.shutdown(wait=True, timeout=5) # Aggiunto timeout anche per shutdown
             except:
                  print("Errore o timeout durante lo shutdown dell'executor scanner.")


        # Nota: i sottoprocessi avviati con Popen (come scrcpy) sono indipendenti
        # e non verranno chiusi automaticamente dall'uscita dell'applicazione GUI.
        # L'utente dovrebbe chiuderli manualmente.

        self.destroy() # Chiude la finestra Tkinter

    def on_treeview_click(self, event):
        """Gestisce il click sulla colonna 'Seleziona' per attivare/disattivare la selezione."""
        region = self.device_tree.identify('region', event.x, event.y)
        if region != 'cell':
            return
        col = self.device_tree.identify_column(event.x)
        if col != '#1':  # Solo la colonna 'Seleziona'
            return
        row_id = self.device_tree.identify_row(event.y)
        if not row_id:
            return
        device_id = self.device_tree.item(row_id, 'values')[1]
        if self.lock_selection:
            return
        if device_id in self.selected_devices:
            self.selected_devices.remove(device_id)
            if device_id in self.device_vars:
                self.device_vars[device_id].set(False)
        else:
            self.selected_devices.add(device_id)
            if device_id in self.device_vars:
                self.device_vars[device_id].set(True)
        self.update_tree_checkmarks()

    def open_adb_terminal_popup(self):
        """Apre una finestra popup per inserire comandi ADB manuali."""
        popup = tk.Toplevel(self)
        popup.title("Terminale ADB Manuale")
        popup.geometry("700x400")

        output = scrolledtext.ScrolledText(popup, height=15)
        output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        input_frame = ttk.Frame(popup)
        input_frame.pack(fill=tk.X, pady=5)
        command_var = tk.StringVar()
        command_entry = ttk.Entry(input_frame, textvariable=command_var)
        command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        def run_manual_adb():
            cmd = command_var.get().strip()
            if not cmd:
                return
            output.insert(tk.END, f"\n> {cmd}\n")
            stdout, stderr = run_adb_command(cmd.split())
            if stdout:
                output.insert(tk.END, stdout)
            if stderr:
                output.insert(tk.END, f"Errore: {stderr}")
            output.see(tk.END)
            command_var.set("")
        ttk.Button(input_frame, text="Esegui", command=run_manual_adb).pack(side=tk.RIGHT, padx=5)
        command_entry.bind('<Return>', lambda e: run_manual_adb())
        command_entry.focus()


class ADBTerminal(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Terminal output
        self.output = scrolledtext.ScrolledText(self, height=10)
        self.output.pack(fill=tk.BOTH, expand=True)
        
        # Command input
        input_frame = ttk.Frame(self)
        input_frame.pack(fill=tk.X, pady=5)
        
        self.command_var = tk.StringVar()
        self.command_entry = ttk.Entry(input_frame, textvariable=self.command_var)
        self.command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        ttk.Button(input_frame, text="Esegui", command=self.execute_command).pack(side=tk.RIGHT, padx=5)
        
        # Bind Enter key
        self.command_entry.bind('<Return>', lambda e: self.execute_command())
        
    def execute_command(self):
        command = self.command_var.get().strip()
        if not command:
            return
            
        self.output.insert(tk.END, f"\n> {command}\n")
        stdout, stderr = run_adb_command(command.split())
        
        if stdout:
            self.output.insert(tk.END, stdout)
        if stderr:
            self.output.insert(tk.END, f"Errore: {stderr}")
            
        self.output.see(tk.END)
        self.command_var.set("")


if __name__ == "__main__":
    app = ADBGui()
    try:
        app.mainloop()
    except tk.TclError:
        pass