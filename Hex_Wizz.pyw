import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox, simpledialog
import binascii
import re
import string

class HexEditor:
    def __init__(self, root):
        self.root = root
        self.root.title("Hex Wizz")
        self.root.geometry("750x600")
        
        self.editor_state = {
            'file_path': None,
            'content': bytearray(),
            'original_content': bytearray(),
            'last_content': bytearray(),
            'mod_track_window': None,
            'modifications': {},
            'mod_track_tree': None,
            'compare_files': [None, None],
            'compare_window': None
        }
        
        self.create_widgets()

    def create_widgets(self):
        menubar = tk.Menu(self.root)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open", command=self.editor_open_file)
        file_menu.add_command(label="Save", command=self.editor_save_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        compare_menu = tk.Menu(menubar, tearoff=0)
        compare_menu.add_command(label="Select File 1", command=lambda: self.select_compare_file(0))
        compare_menu.add_command(label="Select File 2", command=lambda: self.select_compare_file(1))
        compare_menu.add_command(label="Find Differences", command=self.find_differences)
        menubar.add_cascade(label="Compare", menu=compare_menu)
        
        search_menu = tk.Menu(menubar, tearoff=0)
        search_menu.add_command(label="Search", command=self.open_search_window)
        search_menu.add_command(label="Find Strings", command=self.open_find_strings_window)
        menubar.add_cascade(label="Search", menu=search_menu)
        
        self.root.config(menu=menubar)
        
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        menu_frame = tk.Frame(main_frame)
        menu_frame.pack(fill="x", padx=5, pady=5)
        
        goto_offset_button = tk.Button(menu_frame, text="Goto Offset", 
                                     command=self.editor_goto_offset)
        goto_offset_button.pack(side="left", padx=2)
        
        mod_track_button = tk.Button(menu_frame, text="Mod Track", 
                                   command=self.open_mod_track_window)
        mod_track_button.pack(side="left", padx=2)
        
        converter_frame = tk.Frame(menu_frame)
        converter_frame.pack(side="left", padx=10)
        
        tk.Label(converter_frame, text="Hex:").pack(side="left")
        
        self.hex_entry = tk.Entry(converter_frame, width=8)
        self.hex_entry.pack(side="left", padx=2)
        self.hex_entry.insert(0, "00")
        self.hex_entry.bind("<KeyRelease>", lambda e: self.on_hex_entry_key(e, self.hex_entry, self.int_entry))
        
        convert_button = tk.Button(converter_frame, text="⇄", 
                                 command=lambda: self.toggle_conversion(self.hex_entry, self.int_entry),
                                 width=3)
        convert_button.pack(side="left", padx=2)
        
        tk.Label(converter_frame, text="Int:").pack(side="left")
        
        self.int_entry = tk.Entry(converter_frame, width=8)
        self.int_entry.pack(side="left", padx=2)
        self.int_entry.insert(0, "0")
        self.int_entry.bind("<KeyRelease>", lambda e: self.on_int_entry_key(e, self.int_entry, self.hex_entry))
        
        self.hex_entry.bind("<FocusIn>", lambda e: self.hex_entry.select_range(0, 'end'))
        self.int_entry.bind("<FocusIn>", lambda e: self.int_entry.select_range(0, 'end'))
        
        self.text = tk.Text(main_frame, wrap="none", font=("Courier", 10))
        self.text.pack(expand=1, fill="both", padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(self.text)
        scrollbar.pack(side="right", fill="y")
        self.text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.text.yview)
        
        self.text.tag_configure("highlight", background="lightblue")
        self.text.tag_configure("modified", foreground="orange")
        self.text.tag_configure("diff", foreground="red")
        self.text.tag_configure("string_highlight", background="lightgreen")
        
        self.text.bind("<KeyRelease>", lambda e: self.track_text_edits())
        
        
    def open_find_strings_window(self):
        if not self.editor_state['content']:
            messagebox.showwarning("Warning", "No file is currently open.")
            return
            
        strings_window = tk.Toplevel(self.root)
        strings_window.title("Find Strings")
        strings_window.geometry("500x400")
        
        self.string_search_state = {
            'current_pos': 0,
            'found_positions': [],
            'search_window': strings_window
        }
        
        main_frame = tk.Frame(strings_window)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        options_frame = ttk.LabelFrame(main_frame, text="String Search Options")
        options_frame.pack(fill="x", padx=5, pady=5)
        
        self.string_search_type = tk.StringVar(value="auto")
        
        tk.Radiobutton(options_frame, text="Auto-find strings (min/max length)", 
                      variable=self.string_search_type, value="auto").pack(anchor="w")
        tk.Radiobutton(options_frame, text="Search for specific string", 
                      variable=self.string_search_type, value="specific").pack(anchor="w")
        
        auto_frame = ttk.Frame(options_frame)
        auto_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(auto_frame, text="Min length:").pack(side="left")
        self.min_length_entry = tk.Entry(auto_frame, width=5)
        self.min_length_entry.pack(side="left", padx=5)
        self.min_length_entry.insert(0, "4")
        
        tk.Label(auto_frame, text="Max length:").pack(side="left")
        self.max_length_entry = tk.Entry(auto_frame, width=5)
        self.max_length_entry.pack(side="left", padx=5)
        self.max_length_entry.insert(0, "50")
        
        specific_frame = ttk.Frame(options_frame)
        specific_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(specific_frame, text="String:").pack(side="left")
        self.specific_string_entry = tk.Entry(specific_frame)
        self.specific_string_entry.pack(fill="x", expand=True, padx=5)
        
        punct_frame = ttk.LabelFrame(options_frame, text="Ignore these punctuation characters:")
        punct_frame.pack(fill="x", padx=5, pady=5)
        
        self.punct_vars = {}
        punct_chars = string.punctuation
        
        rows = [punct_chars[i:i+10] for i in range(0, len(punct_chars), 10)]
        
        for row in rows:
            row_frame = tk.Frame(punct_frame)
            row_frame.pack(fill="x")
            for char in row:
                var = tk.BooleanVar(value=True)
                self.punct_vars[char] = var
                cb = tk.Checkbutton(row_frame, text=char, variable=var)
                cb.pack(side="left")
        
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill="x", padx=5, pady=5)
        
        search_button = tk.Button(button_frame, text="Find Strings", command=self.find_strings)
        search_button.pack(side="left", padx=2)
        
        find_next_button = tk.Button(button_frame, text="Find Next", command=lambda: self.find_next('string'))
        find_next_button.pack(side="left", padx=2)
        
        find_prev_button = tk.Button(button_frame, text="Find Previous", command=lambda: self.find_previous('string'))
        find_prev_button.pack(side="left", padx=2)
        
        results_frame = ttk.LabelFrame(main_frame, text="Results")
        results_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.string_results_text = tk.Text(results_frame, wrap="word", height=10)
        self.string_results_text.pack(fill="both", expand=True, padx=2, pady=2)
        
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.string_results_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.string_results_text.config(yscrollcommand=scrollbar.set)
        
        self.string_results_text.tag_configure("result", background="white")
        self.string_results_text.tag_configure("selected", background="lightblue")
        
        self.string_results_text.bind("<Double-Button-1>", self.on_string_result_click)

    def find_strings(self):
        if not self.editor_state['content']:
            messagebox.showwarning("Warning", "No file is currently open.")
            return
            
        content = self.editor_state['content']
        search_type = self.string_search_type.get()
        
        ignore_chars = [char for char, var in self.punct_vars.items() if var.get()]
        
        if search_type == "auto":
            try:
                min_len = int(self.min_length_entry.get())
                max_len = int(self.max_length_entry.get())
                if min_len <= 0 or max_len <= 0 or min_len > max_len:
                    raise ValueError("Invalid length range")
            except ValueError:
                messagebox.showerror("Error", "Please enter valid min and max lengths")
                return
                
            found_strings = self.find_strings_in_content(content, min_len, max_len, ignore_chars)
        else:
            search_str = self.specific_string_entry.get()
            if not search_str:
                messagebox.showwarning("Warning", "Please enter a string to search for")
                return
                
            found_strings = self.find_specific_string(content, search_str, ignore_chars)
        
        if not found_strings:
            self.string_results_text.delete(1.0, tk.END)
            self.string_results_text.insert(tk.END, "No strings found matching criteria")
            return
            
        self.string_search_state['found_positions'] = found_strings
        self.string_search_state['current_pos'] = 0
        
        self.update_string_results_display()
        
        self.highlight_current_string_match()

    def find_strings_in_content(self, content, min_len, max_len, ignore_chars):
        strings = []
        current_str = ""
        current_start = None
        
        for i, byte in enumerate(content):
            if 32 <= byte <= 126:
                char = chr(byte)
                if char in ignore_chars:
                    if current_str and len(current_str) >= min_len:
                        strings.append((current_start, current_start + len(current_str) - 1, current_str))
                    current_str = ""
                    current_start = None
                else:
                    if current_start is None:
                        current_start = i
                    current_str += char
            else:
                if current_str and len(current_str) >= min_len:
                    strings.append((current_start, current_start + len(current_str) - 1, current_str))
                current_str = ""
                current_start = None
            
            if current_str and len(current_str) == max_len:
                strings.append((current_start, current_start + len(current_str) - 1, current_str))
                current_str = ""
                current_start = None
        
        if current_str and len(current_str) >= min_len:
            strings.append((current_start, current_start + len(current_str) - 1, current_str))
        
        return strings

    def find_specific_string(self, content, search_str, ignore_chars):
        search_bytes = []
        for char in search_str:
            if char in ignore_chars:
                continue
            search_bytes.append(ord(char))
        
        if not search_bytes:
            return []
            
        matches = []
        for i in range(len(content) - len(search_bytes) + 1):
            match = True
            for j, byte in enumerate(search_bytes):
                if content[i + j] != byte:
                    match = False
                    break
            if match:
                matches.append((i, i + len(search_bytes) - 1, search_str))
        
        return matches

    def update_string_results_display(self):
        self.string_results_text.delete(1.0, tk.END)
        
        if not self.string_search_state['found_positions']:
            self.string_results_text.insert(tk.END, "No strings found matching criteria")
            return
            
        for i, (start, end, string) in enumerate(self.string_search_state['found_positions']):
            tag = "selected" if i == self.string_search_state['current_pos'] else "result"
            self.string_results_text.insert(tk.END, f"0x{start:08X}-0x{end:08X}: {string}\n", tag)

    def highlight_current_string_match(self):
        if not self.string_search_state['found_positions']:
            return
            
        current_pos = self.string_search_state['current_pos']
        start, end, _ = self.string_search_state['found_positions'][current_pos]
        
        self.text.tag_remove("string_highlight", "1.0", tk.END)
        
        start_line = (start // 16) + 3
        end_line = (end // 16) + 3
        
        for offset in range(start, end + 1):
            line_num = (offset // 16) + 3
            hex_start = 10 + (offset % 16) * 3
            hex_end = hex_start + 2
            self.text.tag_add("string_highlight", f"{line_num}.{hex_start}", f"{line_num}.{hex_end}")
        
        self.text.see(f"{start_line}.0")
        
        self.update_string_results_display()
        #messagebox.showinfo("String Search", 
        #           f"Match {current_pos + 1} of {len(self.string_search_state['found_positions'])}")

    def on_string_result_click(self, event):
        index = self.string_results_text.index(f"@{event.x},{event.y}")
        line_num = int(index.split('.')[0])
        
        if line_num - 1 < len(self.string_search_state['found_positions']):
            self.string_search_state['current_pos'] = line_num - 1
            self.highlight_current_string_match()

    
    


    def select_compare_file(self, index):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, "rb") as file:
                    self.editor_state['compare_files'][index] = (file_path, file.read())
                    messagebox.showinfo("Info", f"File {index+1} selected: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not open file: {e}")

    def find_differences(self):
        file1 = self.editor_state['compare_files'][0]
        file2 = self.editor_state['compare_files'][1]
        
        if file1 is None or file2 is None:
            messagebox.showwarning("Warning", "Please select both files to compare.")
            return

        content1 = file1[1]
        content2 = file2[1]

        val1 = simpledialog.askinteger("Input", "Enter the value in File 1 (hex) or Cancel for all differences:", 
                                      minvalue=0, maxvalue=255)
        val2 = simpledialog.askinteger("Input", "Enter the value in File 2 (hex) or Cancel for all differences:", 
                                      minvalue=0, maxvalue=255)

        if self.editor_state['compare_window'] is None or not self.editor_state['compare_window'].winfo_exists():
            compare_window = tk.Toplevel(self.root)
            compare_window.title("Comparison Results")
            compare_window.geometry("800x600")
            self.editor_state['compare_window'] = compare_window
            
            diff_text = tk.Text(compare_window, wrap="none", font=("Courier", 10))
            diff_text.pack(expand=1, fill="both", padx=5, pady=5)
            
            diff_text.tag_configure("diff", foreground="red")
            
            self.editor_state['compare_text'] = diff_text
        else:
            diff_text = self.editor_state['compare_text']
            diff_text.delete(1.0, tk.END)
        
        diff_text.insert(tk.END, f"Comparing:\nFile 1: {file1[0]}\nFile 2: {file2[0]}\n\n")
        diff_text.insert(tk.END, "Offsets with differences:\n")

        address = 0
        max_length = max(len(content1), len(content2))

        for i in range(0, max_length, 16):
            chunk1 = content1[i:i+16] if i < len(content1) else []
            chunk2 = content2[i:i+16] if i < len(content2) else []

            found_diff = False
            for j in range(max(len(chunk1), len(chunk2))):
                b1 = chunk1[j] if j < len(chunk1) else None
                b2 = chunk2[j] if j < len(chunk2) else None
                
                if (val1 is not None and val2 is not None):
                    if b1 == val1 and b2 == val2:
                        found_diff = True
                        break
                else:
                    if b1 != b2:
                        found_diff = True
                        break

            if found_diff:
                diff_text.insert(tk.END, f"{address:08X}\n")

            address += 16

    def open_search_window(self):
        search_window = tk.Toplevel(self.root)
        search_window.title("Search Options")
        search_window.geometry("400x350")
        
        self.search_state = {
            'current_pos': 0,
            'found_positions': [],
            'search_window': search_window
        }
        
        notebook = ttk.Notebook(search_window)
        notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        simple_frame = ttk.Frame(notebook)
        notebook.add(simple_frame, text="Simple Search")
        
        hex_frame = ttk.LabelFrame(simple_frame, text="Hex Search")
        hex_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(hex_frame, text="Hex pattern (use # for wildcard):").pack(anchor="w")
        self.hex_pattern_entry = tk.Entry(hex_frame)
        self.hex_pattern_entry.pack(fill="x", padx=5, pady=2)
        
        hex_button_frame = tk.Frame(hex_frame)
        hex_button_frame.pack(fill="x", pady=5)
        
        search_hex_button = tk.Button(hex_button_frame, text="Search Hex", 
                                    command=self.search_hex_pattern)
        search_hex_button.pack(side="left", padx=2)
        
        find_next_hex = tk.Button(hex_button_frame, text="Find Next", 
                                 command=lambda: self.find_next('hex'))
        find_next_hex.pack(side="left", padx=2)
        
        find_prev_hex = tk.Button(hex_button_frame, text="Find Previous", 
                                 command=lambda: self.find_previous('hex'))
        find_prev_hex.pack(side="left", padx=2)
        
        # Int search
        int_frame = ttk.LabelFrame(simple_frame, text="Integer Search")
        int_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(int_frame, text="Integer value (0-255):").pack(anchor="w")
        self.int_value_entry = tk.Entry(int_frame)
        self.int_value_entry.pack(fill="x", padx=5, pady=2)
        
        int_button_frame = tk.Frame(int_frame)
        int_button_frame.pack(fill="x", pady=5)
        
        search_int_button = tk.Button(int_button_frame, text="Search Integer", 
                                    command=self.search_int_value)
        search_int_button.pack(side="left", padx=2)
        
        find_next_int = tk.Button(int_button_frame, text="Find Next", 
                                command=lambda: self.find_next('int'))
        find_next_int.pack(side="left", padx=2)
        
        find_prev_int = tk.Button(int_button_frame, text="Find Previous", 
                                command=lambda: self.find_previous('int'))
        find_prev_int.pack(side="left", padx=2)
        
        advanced_frame = ttk.Frame(notebook)
        notebook.add(advanced_frame, text="Advanced Search")
        
        pattern1_frame = ttk.LabelFrame(advanced_frame, text="First Pattern")
        pattern1_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(pattern1_frame, text="Hex pattern:").pack(anchor="w")
        self.pattern1_entry = tk.Entry(pattern1_frame)
        self.pattern1_entry.pack(fill="x", padx=5, pady=2)
        
        pattern2_frame = ttk.LabelFrame(advanced_frame, text="Second Pattern")
        pattern2_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(pattern2_frame, text="Hex pattern:").pack(anchor="w")
        self.pattern2_entry = tk.Entry(pattern2_frame)
        self.pattern2_entry.pack(fill="x", padx=5, pady=2)
        
        range_frame = ttk.LabelFrame(advanced_frame, text="Offset Range")
        range_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(range_frame, text="Max offset distance:").pack(anchor="w")
        self.range_entry = tk.Entry(range_frame)
        self.range_entry.pack(fill="x", padx=5, pady=2)
        self.range_entry.insert(0, "10")
        
        adv_button_frame = tk.Frame(advanced_frame)
        adv_button_frame.pack(fill="x", pady=5)
        
        search_advanced_button = tk.Button(adv_button_frame, text="Advanced Search", 
                                         command=self.advanced_search)
        search_advanced_button.pack(side="left", padx=2)
        
        find_next_adv = tk.Button(adv_button_frame, text="Find Next", 
                                command=lambda: self.find_next('adv'))
        find_next_adv.pack(side="left", padx=2)
        
        find_prev_adv = tk.Button(adv_button_frame, text="Find Previous", 
                                command=lambda: self.find_previous('adv'))
        find_prev_adv.pack(side="left", padx=2)

    def find_next(self, search_type):
        if search_type == 'string':
            if not self.string_search_state['found_positions']:
                self.find_strings()
                return
                
            self.string_search_state['current_pos'] += 1
            if self.string_search_state['current_pos'] >= len(self.string_search_state['found_positions']):
                self.string_search_state['current_pos'] = 0
                
            self.highlight_current_string_match()
        else:
            if not self.search_state['found_positions']:
                if search_type == 'hex':
                    self.search_hex_pattern()
                elif search_type == 'int':
                    self.search_int_value()
                elif search_type == 'adv':
                    self.advanced_search()
                return
            
            self.search_state['current_pos'] += 1
            if self.search_state['current_pos'] >= len(self.search_state['found_positions']):
                self.search_state['current_pos'] = 0
                
            self.highlight_current_match()

    def find_previous(self, search_type):
        if search_type == 'string':
            if not self.string_search_state['found_positions']:
                self.find_strings()
                return
                
            self.string_search_state['current_pos'] -= 1
            if self.string_search_state['current_pos'] < 0:
                self.string_search_state['current_pos'] = len(self.string_search_state['found_positions']) - 1  # Wrap around
                
            self.highlight_current_string_match()
        else:
            if not self.search_state['found_positions']:
                if search_type == 'hex':
                    self.search_hex_pattern()
                elif search_type == 'int':
                    self.search_int_value()
                elif search_type == 'adv':
                    self.advanced_search()
                return
            
            self.search_state['current_pos'] -= 1
            if self.search_state['current_pos'] < 0:
                self.search_state['current_pos'] = len(self.search_state['found_positions']) - 1
                
            self.highlight_current_match()


    def highlight_current_match(self):
        if not self.search_state['found_positions']:
            return
        
        current_pos = self.search_state['current_pos']
        if isinstance(self.search_state['found_positions'][0], tuple):
            pos1, pos2 = self.search_state['found_positions'][current_pos]
            self.editor_highlight_byte(pos1)
            self.editor_highlight_byte(pos2)
        else:
            pos = self.search_state['found_positions'][current_pos]
            self.editor_highlight_byte(pos)
        
        #messagebox.showinfo("Search", 
        #                   f"Match {current_pos + 1} of {len(self.search_state['found_positions'])}")

    def search_hex_pattern(self):
        if not self.editor_state['content']:
            messagebox.showwarning("Warning", "No file is currently open.")
            return
            
        hex_pattern = self.hex_pattern_entry.get().strip()
        if not hex_pattern:
            messagebox.showwarning("Warning", "Please enter a hex pattern to search.")
            return
            
        try:
            pattern_bytes = []
            for byte_str in hex_pattern.split():
                if byte_str == '#':
                    pattern_bytes.append(None)
                else:
                    clean_byte = re.sub(r'[^0-9A-Fa-f]', '', byte_str)
                    if not clean_byte:
                        pattern_bytes.append(None)
                    else:
                        pattern_bytes.append(int(clean_byte, 16))
            
            content = self.editor_state['content']
            found_positions = []
            
            for i in range(len(content) - len(pattern_bytes) + 1):
                match = True
                for j, pattern_byte in enumerate(pattern_bytes):
                    if pattern_byte is not None and content[i+j] != pattern_byte:
                        match = False
                        break
                
                if match:
                    found_positions.append(i)
            
            if found_positions:
                self.search_state['found_positions'] = found_positions
                self.search_state['current_pos'] = 0
                self.text.tag_remove("highlight", "1.0", tk.END)
                self.highlight_current_match()
            else:
                messagebox.showinfo("Search", "Pattern not found.")
        except ValueError:
            messagebox.showerror("Error", "Invalid hex pattern")

    def search_int_value(self):
        if not self.editor_state['content']:
            messagebox.showwarning("Warning", "No file is currently open.")
            return
            
        int_str = self.int_value_entry.get().strip()
        if not int_str:
            messagebox.showwarning("Warning", "Please enter an integer value to search.")
            return
            
        try:
            int_val = int(int_str)
            if int_val < 0 or int_val > 255:
                raise ValueError("Value out of range")
                
            content = self.editor_state['content']
            found_positions = []
            
            for i in range(len(content)):
                if content[i] == int_val:
                    found_positions.append(i)
            
            if found_positions:
                self.search_state['found_positions'] = found_positions
                self.search_state['current_pos'] = 0
                self.text.tag_remove("highlight", "1.0", tk.END)
                self.highlight_current_match()
            else:
                messagebox.showinfo("Search", "Value not found.")
        except ValueError:
            messagebox.showerror("Error", "Invalid integer value (must be 0-255)")

    def advanced_search(self):
        if not self.editor_state['content']:
            messagebox.showwarning("Warning", "No file is currently open.")
            return
            
        pattern1 = self.pattern1_entry.get().strip()
        pattern2 = self.pattern2_entry.get().strip()
        range_str = self.range_entry.get().strip()
        
        if not pattern1 or not pattern2:
            messagebox.showwarning("Warning", "Please enter both patterns.")
            return
            
        try:
            def parse_pattern(pattern):
                bytes = []
                for byte_str in pattern.split():
                    if byte_str == '#':
                        bytes.append(None)
                    else:
                        bytes.append(int(byte_str, 16))
                return bytes
            
            pattern1_bytes = parse_pattern(pattern1)
            pattern2_bytes = parse_pattern(pattern2)
            max_range = int(range_str)
            
            content = self.editor_state['content']
            found_positions = []
            
            pattern1_positions = []
            for i in range(len(content) - len(pattern1_bytes) + 1):
                match = True
                for j, pattern_byte in enumerate(pattern1_bytes):
                    if pattern_byte is not None and content[i+j] != pattern_byte:
                        match = False
                        break
                
                if match:
                    pattern1_positions.append(i)
            
            for pos1 in pattern1_positions:
                start = max(0, pos1 - max_range)
                end = min(len(content), pos1 + len(pattern1_bytes) + max_range)
                
                for i in range(start, end - len(pattern2_bytes) + 1):
                    match = True
                    for j, pattern_byte in enumerate(pattern2_bytes):
                        if pattern_byte is not None and content[i+j] != pattern_byte:
                            match = False
                            break
                    
                    if match:
                        found_positions.append((pos1, i))
            
            if found_positions:
                self.search_state['found_positions'] = found_positions
                self.search_state['current_pos'] = 0
                self.text.tag_remove("highlight", "1.0", tk.END)
                self.highlight_current_match()
            else:
                messagebox.showinfo("Search", "No matching pairs found.")
        except ValueError:
            messagebox.showerror("Error", "Invalid input format")

    def toggle_conversion(self, hex_entry, int_entry):
        """Convert in either direction based on which field was last edited"""
        if hex_entry.focus_get() == hex_entry:
            self.convert_hex_to_int(hex_entry, int_entry)
        else:
            self.convert_int_to_hex(int_entry, hex_entry)

    def on_hex_entry_key(self, event, hex_entry, int_entry):
        """Handle hex entry key events"""
        if event.keysym == 'Return':
            self.convert_hex_to_int(hex_entry, int_entry)

    def on_int_entry_key(self, event, int_entry, hex_entry):
        """Handle int entry key events"""
        if event.keysym == 'Return':
            self.convert_int_to_hex(int_entry, hex_entry)

    def convert_hex_to_int(self, hex_entry, int_entry):
        """Convert hex to integer"""
        hex_str = hex_entry.get().strip()
        try:
            if hex_str:
                int_value = int(hex_str, 16)
                int_entry.delete(0, 'end')
                int_entry.insert(0, str(int_value))
        except ValueError:
            messagebox.showerror("Error", "Invalid hexadecimal value")

    def convert_int_to_hex(self, int_entry, hex_entry):
        """Convert integer to hex"""
        int_str = int_entry.get().strip()
        try:
            if int_str:
                hex_value = hex(int(int_str))[2:].upper().zfill(2)
                hex_entry.delete(0, 'end')
                hex_entry.insert(0, hex_value)
        except ValueError:
            messagebox.showerror("Error", "Invalid integer value")
        
    def open_mod_track_window(self):
        if self.editor_state['mod_track_window'] is None or not self.editor_state['mod_track_window'].winfo_exists():
            mod_window = tk.Toplevel(self.root)
            mod_window.title("Modification Tracker")
            mod_window.geometry("350x350")
            
            self.editor_state['mod_track_window'] = mod_window
            
            tree = ttk.Treeview(mod_window, columns=("Offset", "From", "To", "Action"), show="headings")
            tree.heading("Offset", text="Offset")
            tree.heading("From", text="From")
            tree.heading("To", text="To")
            tree.heading("Action", text="Action")
            tree.column("Offset", width=100)
            tree.column("From", width=50)
            tree.column("To", width=50)
            tree.column("Action", width=80)
            tree.pack(fill="both", expand=True, padx=5, pady=5)
            
            self.editor_state['mod_track_tree'] = tree
            
            scrollbar = ttk.Scrollbar(mod_window, orient="vertical", command=tree.yview)
            scrollbar.pack(side="right", fill="y")
            tree.configure(yscrollcommand=scrollbar.set)
            
            self.update_mod_track_window()
            
            mod_window.protocol("WM_DELETE_WINDOW", self.close_mod_track_window)
            
    def close_mod_track_window(self):
        if self.editor_state['mod_track_window']:
            self.editor_state['mod_track_window'].destroy()
            self.editor_state['mod_track_window'] = None
            self.editor_state['mod_track_tree'] = None
    
    def update_mod_track_window(self):
        if self.editor_state['mod_track_tree'] is None:
            return
            
        tree = self.editor_state['mod_track_tree']
        for item in tree.get_children():
            tree.delete(item)
        
        for offset, (old_val, new_val) in self.editor_state['modifications'].items():
            tree.insert("", "end", values=(
                f"{offset:08X}",
                f"{old_val:02X}",
                f"{new_val:02X}",
                "Revert"
            ), tags=("editable",))
        
        tree.tag_bind("editable", "<Button-1>", self.handle_mod_track_click)
        
    def handle_mod_track_click(self, event):
        tree = self.editor_state['mod_track_tree']
        item = tree.identify_row(event.y)
        col = tree.identify_column(event.x)
        
        if item and col == "#4":
            values = tree.item(item, "values")
            offset = int(values[0], 16)
            self.revert_modification(offset)
    
    def revert_modification(self, offset):
        if offset in self.editor_state['modifications']:
            old_val = self.editor_state['modifications'][offset][0]
            self.editor_state['content'][offset] = old_val
            del self.editor_state['modifications'][offset]
            
            self.editor_display_content()
            self.update_mod_track_window()

    def editor_open_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, "rb") as file:
                    self.editor_state['content'] = bytearray(file.read())
                    self.editor_state['original_content'] = bytearray(self.editor_state['content'])
                    self.editor_state['last_content'] = bytearray(self.editor_state['content'])
                    self.editor_state['file_path'] = file_path
                    self.editor_state['modifications'] = {}
                    self.editor_display_content()
                    if self.editor_state['mod_track_tree']:
                        self.update_mod_track_window()
            except Exception as e:
                messagebox.showerror("Error", f"Could not open file: {e}")
                
    def track_text_edits(self):
        """More efficient version that only checks the current line being edited"""
        text = self.text
        
        cursor_pos = text.index(tk.INSERT)
        line_num = int(cursor_pos.split('.')[0])
        
        if line_num < 3:
            return
        
        offset = (line_num - 3) * 16
        
        line_content = text.get(f"{line_num}.0", f"{line_num}.end")
        
        hex_part = line_content[10:58]
        hex_bytes = hex_part.split()
        
        for i, byte_str in enumerate(hex_bytes):
            if len(byte_str) == 2:
                try:
                    new_val = int(byte_str, 16)
                    byte_offset = offset + i
                    
                    if byte_offset < len(self.editor_state['content']):
                        current_val = self.editor_state['content'][byte_offset]
                        
                        if new_val != current_val:
                            self.editor_state['content'][byte_offset] = new_val
                            
                            if byte_offset < len(self.editor_state['original_content']):
                                old_val = self.editor_state['original_content'][byte_offset]
                                if new_val != old_val:
                                    self.editor_state['modifications'][byte_offset] = (old_val, new_val)
                                elif byte_offset in self.editor_state['modifications']:
                                    del self.editor_state['modifications'][byte_offset]
                except ValueError:
                    pass
        
        self.editor_state['last_content'] = bytearray(self.editor_state['content'])
        
        self.highlight_modified_bytes_in_line(line_num)
        
        if self.editor_state['mod_track_tree']:
            self.update_mod_track_window()
            
    def highlight_modified_bytes_in_line(self, line_num):
        text = self.text
        content = self.editor_state['content']
        original = self.editor_state['original_content']
        
        text.tag_remove("modified", f"{line_num}.0", f"{line_num}.end")
        
        offset = (line_num - 3) * 16
        
        for i in range(16):
            byte_offset = offset + i
            if byte_offset >= len(content) or byte_offset >= len(original):
                break
                
            if content[byte_offset] != original[byte_offset]:
                hex_start = 10 + i * 3
                hex_end = hex_start + 2
                text.tag_add("modified", f"{line_num}.{hex_start}", f"{line_num}.{hex_end}")
            
    def highlight_modified_bytes(self):
        text = self.text
        content = self.editor_state['content']
        original = self.editor_state['last_content']
        
        text.tag_remove("modified", "1.0", tk.END)
        
        if len(content) != len(original):
            return
            
        address = 0
        for i in range(0, len(content), 16):
            line_num = i // 16 + 3
            line_start = f"{line_num}.0"
            
            for j in range(16):
                if i + j >= len(content):
                    break
                    
                if content[i+j] != original[i+j]:
                    hex_start = 10 + j * 3
                    hex_end = hex_start + 2
                    text.tag_add("modified", f"{line_num}.{hex_start}", f"{line_num}.{hex_end}")
                    
            address += 16

    def editor_save_file(self):
        if len(self.editor_state['content']) == 0:
            messagebox.showwarning("Warning", "No content to save.")
            return
            
        if not self.editor_state['modifications']:
            messagebox.showinfo("Info", "No modifications to save.")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save File As",
            defaultextension=".bin",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, "wb") as file:
                file.write(self.editor_state['content'])
            
            self.editor_state['original_content'] = bytearray(self.editor_state['content'])
            self.editor_state['modifications'] = {}
            
            if self.editor_state['mod_track_tree']:
                self.update_mod_track_window()
                
            messagebox.showinfo("Success", f"File saved successfully as:\n{file_path}")
            self.editor_state['file_path'] = file_path
        except Exception as e:
            messagebox.showerror("Error", f"Could not save file: {e}")

    def editor_display_content(self):
        text = self.text
        content = self.editor_state['content']
        
        text.delete(1.0, tk.END)
        
        header = "Offset    "
        hex_header = ""
        ascii_header = "  "
        
        for i in range(16):
            hex_header += f"{i:02X} "
        
        for i in range(16):
            ascii_header += f"{i:1X}"
        
        text.insert(tk.END, f"{header}{hex_header} {ascii_header}\n")
        text.insert(tk.END, ("-" * len(header)) + " " + ("-" * len(hex_header)) + " " + ("-" * len(ascii_header)) + "\n")
        
        address = 0
        for i in range(0, len(content), 16):
            chunk = content[i:i+16]
            hex_bytes = " ".join(f"{b:02X}" for b in chunk)
            ascii_bytes = "".join(chr(b) if 32 <= b <= 127 else "." for b in chunk)
            text.insert(tk.END, f"{address:08X}  {hex_bytes:<48}  {ascii_bytes}\n")
            address += 16

    def editor_goto_offset(self):
        if not self.editor_state['content']:
            messagebox.showwarning("Warning", "No file is currently open.")
            return
            
        offset_str = simpledialog.askstring("Goto Offset", "Enter offset in hex (e.g., '000000A0' or 'A0+1'):")
        if offset_str:
            try:
                offset = self.parse_hex_offset(offset_str)
                if offset < 0 or offset >= len(self.editor_state['content']):
                    messagebox.showwarning("Warning", f"Offset out of range (0-{len(self.editor_state['content'])-1:08X})")
                    return
                self.editor_highlight_byte(offset)
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid offset format: {e}")

    def parse_hex_offset(self, offset_str):
        offset_str = offset_str.replace(" ", "")
        
        if '+' in offset_str:
            parts = offset_str.split('+')
            if len(parts) != 2:
                raise ValueError("Invalid offset addition format")
            base = int(parts[0], 16)
            add = int(parts[1], 10)
            return base + add
        else:
            return int(offset_str, 16)

    def editor_highlight_byte(self, offset):
        text = self.text
        content = self.editor_state['content']
        
        line_num = (offset // 16) + 3
        line_start = f"{line_num}.0"
        line_end = f"{line_num + 1}.0"
        
        hex_start = 10 + (offset % 16) * 3
        hex_end = hex_start + 2
        
        text.tag_remove("highlight", "1.0", tk.END)
        
        text.tag_add("highlight", f"{line_num}.{hex_start}", f"{line_num}.{hex_end}")
        
        text.see(line_start)

if __name__ == "__main__":
    root = tk.Tk()
    hex_editor = HexEditor(root)
    root.mainloop()