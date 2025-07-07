import os
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, ttk
import threading
import requests
from dotenv import load_dotenv
import platform
import psutil
import json

# Load environment variables
load_dotenv()
api_key = os.getenv("DEEPSEEK_API_KEY")

API_URL = "https://api.deepseek.com/v1/chat/completions"
MODEL = "deepseek-chat"

# Define the ticket file
TICKET_FILE = "tickets.json"

# Ticket categories and priorities
TICKET_CATEGORIES = ["Hardware", "Software", "Network", "Security", "Email", "Printer", "General"]
TICKET_PRIORITIES = ["Low", "Medium", "High", "Critical"]
TICKET_STATUSES = ["Open", "In Progress", "Resolved", "Closed"]

# Predefined example tickets (LIMITED TO 4), stored only in memory, not saved to the file
PREDEFINED_TICKETS = [
    {
        "issue": "Computer running slow", 
        "solution": "1. Press Ctrl + Shift + Esc to open Task Manager.\n2. Click the 'Startup' tab and disable unnecessary apps.\n3. Go to 'Processes' and sort by CPU or memory to find heavy programs.\n4. Run Disk Cleanup (type it in the Start menu).\n5. Uninstall unused programs from Control Panel > Programs and Features.",
        "category": "Hardware",
        "priority": "Medium",
        "status": "Open",
        "created_date": "2024-01-01 10:00:00"
    },
    {
        "issue": "Can't connect to Wi-Fi", 
        "solution": "1. Restart your computer and router.\n2. Go to Settings > Network & Internet > Wi-Fi.\n3. Forget the network and reconnect with your password.\n4. Open Device Manager and update your network adapter drivers.\n5. If still not working, use the built-in Network Troubleshooter.",
        "category": "Network",
        "priority": "High",
        "status": "Open",
        "created_date": "2024-01-01 10:30:00"
    },
    {
        "issue": "Printer not responding", 
        "solution": "1. Check the power and paper tray.\n2. Restart the printer and your computer.\n3. Reinstall the printer drivers.\n4. Make sure the printer is connected to the correct network.\n5. Check for any error messages on the printer display.",
        "category": "Printer",
        "priority": "Medium",
        "status": "Open",
        "created_date": "2024-01-01 11:00:00"
    },
    {
        "issue": "Computer screen flickering", 
        "solution": "1. Update your display drivers.\n2. Check for loose or damaged cables.\n3. Adjust screen refresh rate (Settings > Display > Advanced display settings).\n4. If using a laptop, try connecting to an external monitor.",
        "category": "Hardware",
        "priority": "Low",
        "status": "Open",
        "created_date": "2024-01-01 11:30:00"
    }
]

messages = [
    {"role": "system", "content": "You are a helpful IT helpdesk assistant. Answer only IT and computer-related questions. When asked for more details or to expand, respond with clear, friendly, and step-by-step guidance. Keep a relaxed and conversational tone, but stay focused on solving IT issues."}
]

# Load or initialize ticket list from the saved file
def load_tickets():
    if os.path.exists(TICKET_FILE) and os.path.getsize(TICKET_FILE) > 0:  # Ensure the file exists and is not empty
        try:
            with open(TICKET_FILE, "r") as f:
                tickets = json.load(f)
                if tickets:
                    return tickets  # Only load user-added tickets
        except (json.JSONDecodeError, Exception):
            # If there's an error reading the file, start fresh
            return []
    return []  # Return an empty list if no tickets are saved

# Function to clear the tickets file if it contains duplicate/predefined tickets
def clear_tickets_file():
    """Clear the tickets.json file to start fresh with only user-added tickets"""
    with open(TICKET_FILE, "w") as f:
        json.dump([], f, indent=2)

def save_tickets(tickets):
    with open(TICKET_FILE, "w") as f:
        json.dump(tickets, f, indent=2)

# Load the tickets (user-added ones)
# First, clear the tickets file to remove duplicates and predefined tickets
clear_tickets_file()
user_tickets = load_tickets()

# Get system info
def get_device_info():
    try:
        # Basic system info
        system_info = f"System: {platform.system()} {platform.release()}\n"
        system_info += f"Version: {platform.version()}\n"
        system_info += f"Architecture: {platform.architecture()[0]}\n"
        system_info += f"Machine: {platform.machine()}\n"
        system_info += f"Node: {platform.node()}\n\n"
        
        # CPU information
        system_info += f"Processor: {platform.processor()}\n"
        system_info += f"CPU Cores (Physical): {psutil.cpu_count(logical=False)}\n"
        system_info += f"CPU Cores (Logical): {psutil.cpu_count(logical=True)}\n"
        system_info += f"CPU Frequency: {psutil.cpu_freq().current:.2f} MHz\n"
        system_info += f"CPU Usage: {psutil.cpu_percent(interval=1)}%\n\n"
        
        # Memory information
        memory = psutil.virtual_memory()
        system_info += f"Total RAM: {round(memory.total / (1024 ** 3), 2)} GB\n"
        system_info += f"Available RAM: {round(memory.available / (1024 ** 3), 2)} GB\n"
        system_info += f"Used RAM: {round(memory.used / (1024 ** 3), 2)} GB\n"
        system_info += f"RAM Usage: {memory.percent}%\n\n"
        
        # Disk information
        disk = psutil.disk_usage('/')
        system_info += f"Total Disk Space: {round(disk.total / (1024 ** 3), 2)} GB\n"
        system_info += f"Used Disk Space: {round(disk.used / (1024 ** 3), 2)} GB\n"
        system_info += f"Free Disk Space: {round(disk.free / (1024 ** 3), 2)} GB\n"
        system_info += f"Disk Usage: {round((disk.used / disk.total) * 100, 1)}%\n\n"
        
        # Network information
        network = psutil.net_io_counters()
        system_info += f"Bytes Sent: {round(network.bytes_sent / (1024 ** 2), 2)} MB\n"
        system_info += f"Bytes Received: {round(network.bytes_recv / (1024 ** 2), 2)} MB\n\n"
        
        # Boot time
        boot_time = psutil.boot_time()
        from datetime import datetime
        boot_time_formatted = datetime.fromtimestamp(boot_time).strftime("%Y-%m-%d %H:%M:%S")
        system_info += f"Boot Time: {boot_time_formatted}\n"
        
        # Battery info (if available)
        try:
            battery = psutil.sensors_battery()
            if battery:
                system_info += f"Battery: {battery.percent}%"
                if battery.power_plugged:
                    system_info += " (Plugged In)"
                else:
                    system_info += f" (Time Left: {battery.secsleft // 3600}h {(battery.secsleft % 3600) // 60}m)"
                system_info += "\n"
        except:
            pass  # Battery info not available on some systems
            
        return system_info
        
    except Exception as e:
        return f"Error getting system information: {str(e)}"

# Show device info in a new window (no clipboard copy)
def show_device_info():
    info_window = tk.Toplevel(window)
    info_window.title("Device Info")
    info_window.geometry("700x500")
    info_window.resizable(True, True)

    device_info = get_device_info()
    
    # Use a text widget with scrollbar for better display
    text_widget = scrolledtext.ScrolledText(info_window, wrap=tk.WORD, font=("Consolas", 11), 
                                          bg="white", fg="black", state='normal')
    text_widget.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    
    text_widget.insert(tk.END, device_info)
    text_widget.config(state='disabled')  # Make it read-only

# Define the send function
def send():
    user_input = entry_text.get("1.0", tk.END).strip()
    if not user_input:
        return

    chat_log.config(state='normal')
    chat_log.insert(tk.END, f"You: {user_input}\n")
    chat_log.insert(tk.END, "Bot: Thinking...\n")
    chat_log.config(state='disabled')
    chat_log.see(tk.END)

    messages.append({"role": "user", "content": user_input})
    entry_text.delete("1.0", tk.END)

    threading.Thread(target=fetch_response, args=(user_input,), daemon=True).start()

# Fetch AI response
def fetch_response(user_input):
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    data = {
        "model": MODEL,
        "messages": messages,
        "temperature": 0.7
    }
    try:
        response = requests.post(API_URL, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        bot_message = result['choices'][0]['message']['content']
    except Exception as e:
        bot_message = f"[Error] {str(e)}"

    messages.append({"role": "assistant", "content": bot_message})
    update_chat_log(bot_message)

# Update the chat log UI
def update_chat_log(bot_message):
    chat_log.config(state='normal')
    chat_log.delete("end-2l", "end-1l")  # Remove 'Thinking...'
    chat_log.insert(tk.END, f"Bot: {bot_message}\n")  # Correct f-string with newline
    chat_log.config(state='disabled')
    chat_log.see(tk.END)

# Show tickets with enhanced categorization
def show_ticket_list():
    ticket_window = tk.Toplevel(window)
    ticket_window.title("IT Ticket Management")
    ticket_window.geometry("900x600")
    ticket_window.resizable(True, True)

    # Create main frame
    main_frame = tk.Frame(ticket_window)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Filter frame
    filter_frame = tk.Frame(main_frame)
    filter_frame.pack(fill=tk.X, pady=(0, 10))

    # Category filter
    tk.Label(filter_frame, text="Category:", font=("Arial", 10)).grid(row=0, column=0, padx=5, sticky="w")
    category_var = tk.StringVar(value="All")
    category_combo = tk.OptionMenu(filter_frame, category_var, "All", *TICKET_CATEGORIES)
    category_combo.grid(row=0, column=1, padx=5, sticky="w")

    # Priority filter
    tk.Label(filter_frame, text="Priority:", font=("Arial", 10)).grid(row=0, column=2, padx=5, sticky="w")
    priority_var = tk.StringVar(value="All")
    priority_combo = tk.OptionMenu(filter_frame, priority_var, "All", *TICKET_PRIORITIES)
    priority_combo.grid(row=0, column=3, padx=5, sticky="w")

    # Status filter
    tk.Label(filter_frame, text="Status:", font=("Arial", 10)).grid(row=0, column=4, padx=5, sticky="w")
    status_var = tk.StringVar(value="All")
    status_combo = tk.OptionMenu(filter_frame, status_var, "All", *TICKET_STATUSES)
    status_combo.grid(row=0, column=5, padx=5, sticky="w")

    # Search box
    tk.Label(filter_frame, text="Search:", font=("Arial", 10)).grid(row=0, column=6, padx=5, sticky="w")
    search_var = tk.StringVar()
    search_entry = tk.Entry(filter_frame, textvariable=search_var, width=15)
    search_entry.grid(row=0, column=7, padx=5, sticky="w")

    # Ticket list frame
    list_frame = tk.Frame(main_frame)
    list_frame.pack(fill=tk.BOTH, expand=True)

    # Create treeview for better ticket display
    columns = ("Issue", "Category", "Priority", "Status", "Date")
    tree = tk.ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
    
    # Configure columns
    tree.heading("Issue", text="Issue")
    tree.heading("Category", text="Category")
    tree.heading("Priority", text="Priority")
    tree.heading("Status", text="Status")
    tree.heading("Date", text="Created Date")
    
    tree.column("Issue", width=350)
    tree.column("Category", width=100)
    tree.column("Priority", width=80)
    tree.column("Status", width=100)
    tree.column("Date", width=150)

    # Add scrollbar to treeview
    scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Combine predefined and user tickets
    all_tickets = PREDEFINED_TICKETS + user_tickets

    def update_ticket_list():
        # Clear existing items
        for item in tree.get_children():
            tree.delete(item)
        
        # Filter tickets
        category_filter = category_var.get()
        priority_filter = priority_var.get()
        status_filter = status_var.get()
        search_filter = search_var.get().lower()
        
        for idx, ticket in enumerate(all_tickets):
            # Apply filters
            if category_filter != "All" and ticket.get("category", "General") != category_filter:
                continue
            if priority_filter != "All" and ticket.get("priority", "Medium") != priority_filter:
                continue
            if status_filter != "All" and ticket.get("status", "Open") != status_filter:
                continue
            if search_filter and search_filter not in ticket["issue"].lower():
                continue
            
            # Add priority color coding
            priority = ticket.get("priority", "Medium")
            if priority == "Critical":
                tag = "critical"
            elif priority == "High":
                tag = "high"
            elif priority == "Medium":
                tag = "medium"
            else:
                tag = "low"
            
            tree.insert("", "end", 
                       values=(ticket["issue"], 
                              ticket.get("category", "General"),
                              ticket.get("priority", "Medium"),
                              ticket.get("status", "Open"),
                              ticket.get("created_date", "N/A")),
                       tags=(tag,))

    # Configure tags for priority colors
    tree.tag_configure("critical", background="#ffcccc")
    tree.tag_configure("high", background="#ffe6cc")
    tree.tag_configure("medium", background="#fff2cc")
    tree.tag_configure("low", background="#e6ffcc")

    # Bind filter changes
    def on_filter_change(*args):
        update_ticket_list()
    
    category_var.trace("w", on_filter_change)
    priority_var.trace("w", on_filter_change)
    status_var.trace("w", on_filter_change)
    search_var.trace("w", on_filter_change)

    def on_ticket_select(event):
        selected_items = tree.selection()
        if selected_items:
            item = tree.item(selected_items[0])
            issue = item["values"][0]
            
            # Find the actual ticket
            selected_ticket = None
            ticket_index = -1
            for idx, ticket in enumerate(all_tickets):
                if ticket["issue"] == issue:
                    selected_ticket = ticket
                    ticket_index = idx
                    break
            
            if selected_ticket:
                show_ticket_details(selected_ticket, ticket_index)

    tree.bind("<Double-1>", on_ticket_select)

    # Initial load
    update_ticket_list()

def show_ticket_details(ticket, ticket_index):
    details_window = tk.Toplevel(window)
    details_window.title("Ticket Details")
    details_window.geometry("600x500")
    details_window.resizable(True, True)

    # Create notebook for tabs
    notebook = tk.ttk.Notebook(details_window)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Details tab
    details_frame = tk.Frame(notebook)
    notebook.add(details_frame, text="Details")

    # Issue
    tk.Label(details_frame, text="Issue:", font=("Arial", 12, "bold")).pack(anchor="w", pady=(10, 5))
    issue_text = tk.Text(details_frame, height=2, wrap=tk.WORD, font=("Arial", 11))
    issue_text.pack(fill=tk.X, padx=10, pady=(0, 10))
    issue_text.insert("1.0", ticket["issue"])
    issue_text.config(state='disabled')

    # Category, Priority, Status
    info_frame = tk.Frame(details_frame)
    info_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

    tk.Label(info_frame, text="Category:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="w", padx=(0, 5))
    tk.Label(info_frame, text=ticket.get("category", "General"), font=("Arial", 10)).grid(row=0, column=1, sticky="w", padx=(0, 20))

    tk.Label(info_frame, text="Priority:", font=("Arial", 10, "bold")).grid(row=0, column=2, sticky="w", padx=(0, 5))
    tk.Label(info_frame, text=ticket.get("priority", "Medium"), font=("Arial", 10)).grid(row=0, column=3, sticky="w", padx=(0, 20))

    tk.Label(info_frame, text="Status:", font=("Arial", 10, "bold")).grid(row=0, column=4, sticky="w", padx=(0, 5))
    tk.Label(info_frame, text=ticket.get("status", "Open"), font=("Arial", 10)).grid(row=0, column=5, sticky="w")

    # Date
    tk.Label(details_frame, text="Created Date:", font=("Arial", 10, "bold")).pack(anchor="w", padx=10, pady=(0, 5))
    tk.Label(details_frame, text=ticket.get("created_date", "N/A"), font=("Arial", 10)).pack(anchor="w", padx=10, pady=(0, 10))

    # Solution
    tk.Label(details_frame, text="Solution:", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
    solution_text = scrolledtext.ScrolledText(details_frame, height=10, wrap=tk.WORD, font=("Arial", 11))
    solution_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
    solution_text.insert("1.0", ticket["solution"])
    solution_text.config(state='disabled')

    # Actions frame
    actions_frame = tk.Frame(details_frame)
    actions_frame.pack(fill=tk.X, padx=10, pady=10)

    # Only show resolve button for user tickets
    if ticket_index >= len(PREDEFINED_TICKETS):
        def resolve_ticket():
            if messagebox.askyesno("Resolve Ticket", "Mark this ticket as resolved?"):
                user_ticket_index = ticket_index - len(PREDEFINED_TICKETS)
                del user_tickets[user_ticket_index]
                save_tickets(user_tickets)
                details_window.destroy()
                messagebox.showinfo("Success", "Ticket has been resolved and removed!")

        resolve_button = tk.Button(actions_frame, text="Resolve Ticket", command=resolve_ticket, 
                                 bg="#4CAF50", fg="white", font=("Arial", 11))
        resolve_button.pack(side=tk.LEFT, padx=(0, 10))

    close_button = tk.Button(actions_frame, text="Close", command=details_window.destroy, 
                           font=("Arial", 11))
    close_button.pack(side=tk.RIGHT)

# Enhanced add ticket function with categorization
def add_ticket():
    add_window = tk.Toplevel(window)
    add_window.title("Add New Ticket")
    add_window.geometry("500x400")
    add_window.resizable(True, True)

    # Issue input
    tk.Label(add_window, text="Issue Description:", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
    issue_text = tk.Text(add_window, height=3, wrap=tk.WORD, font=("Arial", 11))
    issue_text.pack(fill=tk.X, padx=10, pady=(0, 10))

    # Category, Priority, Status selection
    selection_frame = tk.Frame(add_window)
    selection_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

    # Category
    tk.Label(selection_frame, text="Category:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
    category_var = tk.StringVar(value="General")
    category_combo = tk.ttk.Combobox(selection_frame, textvariable=category_var, values=TICKET_CATEGORIES, state="readonly")
    category_combo.grid(row=0, column=1, sticky="w", padx=(10, 20), pady=5)

    # Priority
    tk.Label(selection_frame, text="Priority:", font=("Arial", 10, "bold")).grid(row=0, column=2, sticky="w", pady=5)
    priority_var = tk.StringVar(value="Medium")
    priority_combo = tk.ttk.Combobox(selection_frame, textvariable=priority_var, values=TICKET_PRIORITIES, state="readonly")
    priority_combo.grid(row=0, column=3, sticky="w", padx=(10, 0), pady=5)

    # Status
    tk.Label(selection_frame, text="Status:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky="w", pady=5)
    status_var = tk.StringVar(value="Open")
    status_combo = tk.ttk.Combobox(selection_frame, textvariable=status_var, values=TICKET_STATUSES, state="readonly")
    status_combo.grid(row=1, column=1, sticky="w", padx=(10, 0), pady=5)

    # Solution input
    tk.Label(add_window, text="Solution:", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
    solution_text = scrolledtext.ScrolledText(add_window, height=8, wrap=tk.WORD, font=("Arial", 11))
    solution_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

    # Buttons
    button_frame = tk.Frame(add_window)
    button_frame.pack(fill=tk.X, padx=10, pady=10)

    def save_ticket():
        issue = issue_text.get("1.0", tk.END).strip()
        solution = solution_text.get("1.0", tk.END).strip()
        
        if not issue or not solution:
            messagebox.showerror("Error", "Please fill in both issue and solution fields.")
            return
        
        # Create timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        new_ticket = {
            "issue": issue,
            "solution": solution,
            "category": category_var.get(),
            "priority": priority_var.get(),
            "status": status_var.get(),
            "created_date": timestamp
        }
        
        user_tickets.append(new_ticket)
        save_tickets(user_tickets)
        add_window.destroy()
        messagebox.showinfo("Success", "Ticket has been added successfully!")

    save_button = tk.Button(button_frame, text="Save Ticket", command=save_ticket, 
                           bg="#4CAF50", fg="white", font=("Arial", 11))
    save_button.pack(side=tk.LEFT, padx=(0, 10))

    cancel_button = tk.Button(button_frame, text="Cancel", command=add_window.destroy, font=("Arial", 11))
    cancel_button.pack(side=tk.RIGHT)

# Function to clear all user-added tickets
def clear_user_tickets():
    if messagebox.askyesno("Clear Tickets", "Are you sure you want to clear all user-added tickets?\n\nThis will not affect the predefined tickets."):
        user_tickets.clear()
        save_tickets(user_tickets)
        messagebox.showinfo("Tickets Cleared", "All user-added tickets have been cleared!")

# Create the GUI
window = tk.Tk()
window.title("IT Helpdesk Bot")
window.geometry("750x750")

chat_log = scrolledtext.ScrolledText(window, wrap=tk.WORD, state='disabled', font=("Arial", 12))
chat_log.pack(padx=15, pady=15, fill=tk.BOTH, expand=True)

entry_text = tk.Text(window, height=4, font=("Arial", 12))
entry_text.pack(padx=15, pady=(0,15), fill=tk.X)
entry_text.bind("<Return>", lambda event: (send(), "break"))

button_frame = tk.Frame(window)
button_frame.pack(pady=(0, 20))

send_button = tk.Button(button_frame, text="Send", command=send, font=("Arial", 12))
send_button.grid(row=0, column=0, padx=10)

copy_info_button = tk.Button(button_frame, text="Show Device Info", command=show_device_info, font=("Arial", 12))
copy_info_button.grid(row=0, column=1, padx=10)

ticket_button = tk.Button(button_frame, text="Show Tickets", command=show_ticket_list, font=("Arial", 12))
ticket_button.grid(row=0, column=2, padx=10)

add_ticket_button = tk.Button(button_frame, text="Add Ticket", command=add_ticket, font=("Arial", 12))
add_ticket_button.grid(row=0, column=3, padx=10)

clear_tickets_button = tk.Button(button_frame, text="Clear User Tickets", command=clear_user_tickets, font=("Arial", 12))
clear_tickets_button.grid(row=0, column=4, padx=10)

window.mainloop()