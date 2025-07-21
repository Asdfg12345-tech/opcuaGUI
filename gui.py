import threading
import time
import queue
import tkinter as tk
import tkinter.font as tkfont
from tkinterdnd2 import DND_ALL, TkinterDnD
from tkinter import ttk, messagebox, simpledialog, filedialog
from opcua import Client, ua
from opcua.ua.uaerrors import BadAttributeIdInvalid, UaStatusCodeError
import json
import os
import re
import time

PROFILES_FILE     = os.path.expanduser('~/.opcua_profiles.json')
SESSION_FILE      = os.path.expanduser('~/.opcua_session.json')
PREFS_FILE        = os.path.expanduser('~/.opcua_prefs.json')
SECURITY_POLICIES = ['NoSecurity', 'Basic128Rsa15', 'Basic256Sha256']
ERROR_LOG         = 'opcua_errors.log'

class GuiHandler:
    """OPC UA Subscription Handler forwarding notifications to a queue."""
    def __init__(self, queue, node_cache, log_func):
        self.queue = queue
        self.node_cache = node_cache
        self.log = log_func

    def datachange_notification(self, node, val, data):
        nid = node.nodeid.to_string()
        name, _ = self.node_cache.get(nid, (nid, None))
        if name.lower() == 'keepalivedummy':
            return
        source_ts = getattr(data, 'SourceTimestamp', '') or time.strftime('%Y-%m-%d %H:%M:%S')
        server_ts = getattr(data, 'ServerTimestamp', '') or time.strftime('%Y-%m-%d %H:%M:%S')
        self.queue.put((nid, name, val, source_ts, server_ts))
        self.log(f"DataChange: {name}={val} at SourceTS={source_ts} ServerTS={server_ts}")    

class OPCUAGuiApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title('OPC UA Client GUI')
        self.geometry('1200x760')
        self.protocol('WM_DELETE_WINDOW', self.on_exit)

        # --- Theming/Prefs ---
        self.prefs = self.load_json(PREFS_FILE) or {}
        self.theme_var = tk.StringVar(value=self.prefs.get("theme", "Light"))
        self.font_var = tk.StringVar(value=self.prefs.get("font", "TkDefaultFont"))
        self.fontsize_var = tk.IntVar(value=self.prefs.get("fontsize", 10))

        # --- Menu for theme/font ---
        menu = tk.Menu(self)
        self.config(menu=menu)
        theme_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="Preferences", menu=theme_menu)
        theme_menu.add_radiobutton(label="Light", variable=self.theme_var, value="Light", command=self._apply_theme)
        theme_menu.add_radiobutton(label="Dark",  variable=self.theme_var, value="Dark",  command=self._apply_theme)
        theme_menu.add_separator()
        theme_menu.add_command(label="Font...", command=self._choose_font)

        

        # --- Logging UI ---
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.main_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.main_frame, text="Main")
        self.log_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.log_tab, text="Log")
        self.log_text = tk.Text(self.log_tab, state=tk.DISABLED, wrap=tk.WORD, height=8)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Button(self.log_tab, text="Clear Log", command=self.clear_log).pack(pady=2)

        self.log_messages = []
        log_frame = ttk.Frame(self.main_frame); log_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var = tk.StringVar(value='Ready')
        self.status_label = ttk.Label(log_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor='w')
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.log_win = None

        # --- Profiles & Session ---
        self.profiles = self.load_json(PROFILES_FILE) or {}
        self.session  = self.load_json(SESSION_FILE) or {}

        # --- Top: Profile + Connection ---
        top = ttk.Frame(self.main_frame); top.pack(fill=tk.X, pady=5, padx=5)
        ttk.Label(top, text='Profile:').pack(side=tk.LEFT)
        self.profile_var = tk.StringVar()
        self.profile_cb  = ttk.Combobox(top, textvariable=self.profile_var,
                             values=list(self.profiles.keys()), state='readonly')
        self.profile_cb.pack(side=tk.LEFT, padx=(0,5))
        self.profile_cb.bind('<<ComboboxSelected>>', self.on_profile_select)
        for txt, cmd in [('Add',self.add_profile),
                         ('Edit',self.edit_profile),
                         ('Delete',self.delete_profile)]:
            ttk.Button(top, text=txt, command=cmd).pack(side=tk.LEFT)
        ttk.Label(top, text='URL:').pack(side=tk.LEFT)
        self.url = tk.StringVar()
        ttk.Entry(top, textvariable=self.url, width=30).pack(side=tk.LEFT, padx=(0,5))
        ttk.Label(top, text='Security:').pack(side=tk.LEFT)
        self.sec_var = tk.StringVar(value=SECURITY_POLICIES[0])
        ttk.Combobox(top, textvariable=self.sec_var,
                     values=SECURITY_POLICIES, width=15).pack(side=tk.LEFT, padx=(0,5))
        ttk.Label(top, text='User:').pack(side=tk.LEFT)
        self.user_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.user_var, width=12).pack(side=tk.LEFT, padx=(0,5))
        ttk.Label(top, text='Pass:').pack(side=tk.LEFT)
        self.pass_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.pass_var, show='*', width=12)\
            .pack(side=tk.LEFT, padx=(0,5))
        for txt, cmd in [('Connect',self.connect), ('Disconnect',self.disconnect)]:
            ttk.Button(top, text=txt, command=cmd).pack(side=tk.LEFT)
        ttk.Button(top, text='Help', command=self.show_help).pack(side=tk.LEFT)
        ttk.Button(top, text='Server Info', command=self.show_server_info).pack(side=tk.LEFT)



        # --- Main Layout: Left Tree / Controls, Right Table / Filter ---
        left = ttk.Frame(self.main_frame); left.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        right= ttk.Frame(self.main_frame); right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # --- Tree + Controls ---
        self.tree = ttk.Treeview(left, show='tree')
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind('<<TreeviewOpen>>', self.on_tree_expand)
        self.tree.bind('<Button-1>',       self.on_tree_click)
        self.tree.bind('<B1-Motion>',      self.on_tree_drag_motion)
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        self._drag_source = None

        # Attribute details panel (below the tree)
        self.attr_text = tk.Text(left, height=6, width=50, bg="#f5f5f5")
        self.attr_text.pack(fill=tk.X, expand=False, padx=3, pady=(5,0))
        self.attr_text.config(state=tk.DISABLED)

        btns = ttk.Frame(left); btns.pack(fill=tk.X, pady=5)
        for txt, cmd in [
            ('Apply', self.apply_sub),
            ('Unsub', self.remove_sel),
            ('Clear', self.clear_all),
            ('Write', self.write_value),
            ('Export Subs', self.export_subs),
            ('Import Subs', self.import_subs),
            ('Exit', self.on_exit)]:
            ttk.Button(btns, text=txt, command=cmd).pack(fill=tk.X)

        # --- Filter + Table ---
        ffrm = ttk.Frame(right); ffrm.pack(fill=tk.X)
        ttk.Label(ffrm, text='Filter:').pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add('write', self.update_table)
        ttk.Entry(ffrm, textvariable=self.filter_var)\
            .pack(side=tk.LEFT, fill=tk.X, expand=True)

        cols = ('Node','NodeId','DataType','Value','ServerTime','WriteTime')
        self.tbl = ttk.Treeview(right, columns=cols, show='headings')
        for c in cols:
            self.tbl.heading(c, text=c, command=lambda c=c: self.sort_col(c,False))
            self.tbl.column(c, stretch=True, width=120)
        self.tbl.pack(fill=tk.BOTH, expand=True)
        self.tbl.drop_target_register(DND_ALL)
        self.tbl.dnd_bind('<<Drop>>', self.on_table_drop)
        self.tbl.bind('<Double-1>', self.on_table_double_click)

        # --- State ---
        self.client       = None
        self.sub          = None
        self.handler      = None
        self.node_cache   = {}
        self.node_map     = {}
        self.subs         = set()
        self.handles      = {}
        self.values       = {}
        self.queue        = queue.Queue()
        self.auto_reconnect = False
        self.after(100, self.proc)

        if self.profiles:
            first = next(iter(self.profiles))
            self.profile_var.set(first)
            self.load_profile_fields(first)

        self._apply_theme()
    # --- Theming/font helpers ---
    def _apply_theme(self):
        s = ttk.Style()
        # Use clam for dark mode, default for light
        if self.theme_var.get() == "Dark":
            s.theme_use('clam')
            s.configure('.', background='#222', foreground='#f3f3f3', fieldbackground='#222')
            s.configure('Treeview', background='#222', fieldbackground='#333', foreground='#f3f3f3')
            s.configure('TLabel', background='#222', foreground='#f3f3f3')
            self['bg'] = '#222'
            self.attr_text.config(bg='#333', fg='#fff')
        else:
            s.theme_use('default')
            s.configure('.', background='#f5f5f5', foreground='#111', fieldbackground='#fff')
            s.configure('Treeview', background='#fff', fieldbackground='#fff', foreground='#111')
            s.configure('TLabel', background='#f5f5f5', foreground='#111')
            self['bg'] = '#f5f5f5'
            self.attr_text.config(bg='#f5f5f5', fg='#222')
        self._apply_font()
        self.save_prefs()

    def _apply_font(self):
        font = (self.font_var.get(), self.fontsize_var.get())
        widgets = [self, self.attr_text, self.tbl, self.tree]
        for w in widgets:
            try:
                w.configure(font=font)
            except: pass

    def _choose_font(self):
        fonts = sorted(set(tkfont.families()))
        top = tk.Toplevel(self)
        top.title("Font/Size")
        tk.Label(top, text="Font:").pack(side=tk.LEFT)
        fcb = ttk.Combobox(top, values=fonts, textvariable=self.font_var)
        fcb.pack(side=tk.LEFT)
        tk.Label(top, text="Size:").pack(side=tk.LEFT)
        scb = ttk.Combobox(top, values=[8,9,10,11,12,14,16,18,20,22,24,28], textvariable=self.fontsize_var)
        scb.pack(side=tk.LEFT)
        def ok():
            self._apply_font()
            self.save_prefs()
            top.destroy()
        ttk.Button(top, text="Apply", command=ok).pack(side=tk.LEFT)

    def save_prefs(self):
        prefs = {
            "theme": self.theme_var.get(),
            "font": self.font_var.get(),
            "fontsize": self.fontsize_var.get()
        }
        try:
            with open(PREFS_FILE,'w') as f:
                json.dump(prefs, f, indent=2)
        except Exception:
            pass

    # --- Logging Helpers ---
    def log(self, msg):
        self.log_messages.append(msg)
        self.status_var.set(msg)
        if self.log_text:
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert('end', msg + '\n')
            self.log_text.see('end')
            self.log_text.config(state=tk.DISABLED)


    def log_error(self, msg):
            with open(ERROR_LOG, 'a') as f:
                f.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + msg + '\n')
            if hasattr(self, 'status_var'):
               self.status_var.set(f"Error: {msg}")
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert('end', f"ERROR: {msg}\n")
            self.log_text.see('end')
            self.log_text.config(state=tk.DISABLED)

    def clear_log(self):
        self.log_messages.clear()
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)
        

    def toggle_log_window(self):
        if self.log_win and tk.Toplevel.winfo_exists(self.log_win):
            self.log_win.destroy(); self.log_win = None
        else:
            self.log_win = tk.Toplevel(self); self.log_win.title('Log')
            txt = tk.Text(self.log_win); txt.pack(fill=tk.BOTH, expand=True)
            for m in self.log_messages: txt.insert('end', m + '\n')

    def show_help(self):
        messagebox.showinfo("Troubleshooting",
            "Common errors and troubleshooting tips:\n"
            "\n"
            "• BadAttributeIdInvalid: Node does not support subscriptions (maybe not a variable).\n"
            "• TimeoutError: Server is not reachable (check network, address, or firewall).\n"
            "• ConnectionRefusedError: Wrong URL, wrong port, or server not running.\n"
            "• ValueError: Tried to write an unsupported value type to the node.\n"
            "• Authentication failed: Check your username and password.\n"
            "\n"
            "See opcua_errors.log for full technical error log."
        )

    # --- Attribute Viewer ---
    def on_tree_select(self, event):
        sels = self.tree.selection()
        if not sels:
            self.attr_text.config(state=tk.NORMAL)
            self.attr_text.delete('1.0', tk.END)
            self.attr_text.config(state=tk.DISABLED)
            return
        nid = sels[0]
        try:
            node = self.client.get_node(nid)
            attrs = {}
            try:
                attrs['NodeId'] = str(node.nodeid)
                attrs['BrowseName'] = str(node.get_browse_name())
                attrs['DisplayName'] = str(node.get_display_name())
                attrs['Description'] = str(node.get_description().Text)
                attrs['NodeClass'] = str(node.get_node_class())
                if attrs['NodeClass'] == 'NodeClass.Variable':
                    try:
                        attrs['DataType'] = str(self.client.get_node(node.get_data_type()).get_browse_name())
                    except: pass
                    try:
                        attrs['ValueRank'] = str(node.get_value_rank())
                    except: pass
                    try:
                        attrs['AccessLevel'] = str(node.get_access_level())
                    except: pass
                    try:
                        val = node.get_value()
                        attrs['Value'] = str(val)
                    except: pass
            except Exception as e:
                attrs['Error'] = str(e)
        except Exception as e:
            attrs = {'Error': str(e)}
        self.attr_text.config(state=tk.NORMAL)
        self.attr_text.delete('1.0', tk.END)
        for k,v in attrs.items():
            self.attr_text.insert(tk.END, f"{k}: {v}\n")
        self.attr_text.config(state=tk.DISABLED)

    # --- Export/Import Subscriptions ---
    def export_subs(self):
        if not self.subs:
            messagebox.showinfo("Export Subscriptions", "No subscriptions to export!")
            return
        prof = self.profile_var.get()
        export = {
            "profile": prof,
            "url": self.url.get(),
            "subs": list(self.subs)
        }
        f = filedialog.asksaveasfilename(
            title="Export Subscriptions",
            filetypes=[("JSON Files", "*.json")],
            defaultextension=".json")
        if not f: return
        try:
            with open(f, 'w') as fp:
                json.dump(export, fp, indent=2)
            self.log(f"Exported to {os.path.basename(f)}")    
            messagebox.showinfo("Export Subscriptions", f"Exported to {os.path.basename(f)}")
        except Exception as e:
            self.log_error(f"Export error: {e}")
            messagebox.showerror("Export Failed", str(e))

    def import_subs(self):
        f = filedialog.askopenfilename(
            title="Import Subscriptions",
            filetypes=[("JSON Files", "*.json")])
        if not f: return
        try:
            with open(f, 'r') as fp:
                data = json.load(fp)
            profile = data.get("profile")
            url = data.get("url")
            subs = data.get("subs", [])
            # Set profile, url and connect
            if profile and profile in self.profiles:
                self.profile_var.set(profile)
                self.load_profile_fields(profile)
            if url:
                self.url.set(url)
            # (Re-)Connect if needed
            if not self.client:
                self.connect()
            elif self.url.get() != url:
                self.url.set(url)
                self.connect()
            # Mark all subs in tree
            self.update()
            self.after(800, lambda:self._import_mark_and_apply(subs))
            self.log(f"Imported {len(subs)} subscriptions from {os.path.basename(f)}")
            messagebox.showinfo("Import Subscriptions", f"Imported {len(subs)} subscriptions from {os.path.basename(f)}")
        except Exception as e:
            self.log_error(f"Import error: {e}")
            messagebox.showerror("Import Failed", str(e))

    def _import_mark_and_apply(self, subs):
        # Mark in the tree
        for nid in subs:
            if self.tree.exists(nid):
                t = self.tree.item(nid, 'text')
                if t.startswith('[ ]'):
                    self.tree.item(nid, text='[x]' + t[3:])
        self.apply_sub()

    # --- Lazy-load Tree ---
    def on_tree_expand(self, event):
        iid = self.tree.focus()
        if f"{iid}_dummy" in self.tree.get_children(iid):
            self.tree.delete(f"{iid}_dummy")
            ua_node = self.client.get_node(iid)
            self._populate_node(ua_node, iid)

    def _populate_node(self, ua_node, parent):
        from opcua import ua as ua_mod
        try: kids = ua_node.get_children()
        except Exception as e:
            self.log_error(f"Error reading children: {e}")
            return
        for c in kids:
            try:
                cls = c.get_node_class(); nm = c.get_browse_name().Name
                nid = c.nodeid.to_string()
            except Exception as e:
                self.log_error(f"Node browse error: {e}")
                continue
            tag = 'var' if cls==ua_mod.NodeClass.Variable else ''
            txt = f'[ ] {nm}' if tag=='var' else nm
            self.tree.insert(parent,'end',nid,text=txt,tags=(tag,))
            try:
                if c.get_children():
                    self.tree.insert(nid,'end',f'{nid}_dummy')
            except Exception as e:
                self.log_error(f"Node child error: {e}")
                pass

    # --- Tree Drag & Click ---
    def on_tree_drag_motion(self, event):
        iid = self.tree.identify_row(event.y)
        if iid and 'var' in self.tree.item(iid,'tags'):
            self._drag_source = iid

    def on_tree_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid or 'var' not in self.tree.item(iid,'tags'): return
        txt = self.tree.item(iid,'text')
        new = '[x]'+txt[3:] if txt.startswith('[ ]') else '[ ]'+txt[3:]
        self.tree.item(iid, text=new)

    # --- Table Drop (uses drag_source) ---
    def on_table_drop(self, event):
        nid = self._drag_source
        if not nid or nid not in self.node_map:
            self.log_error('Dropped node not recognized')
            messagebox.showerror('Error','Dropped node not recognized')
            return
        txt = self.tree.item(nid,'text')
        if txt.startswith('[ ]'):
            self.tree.item(nid,text='[x]'+txt[3:])
        else:
            self.tree.item(nid,text='[ ]'+txt[3:])
        self.apply_sub()
        self._drag_source = None

    # --- JSON Persistence ---
    def load_json(self, path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            # Only log to UI if logging is set up
            if hasattr(self, 'status_var'):
                self.log_error(f"Load JSON {path} error: {e}")
            else:
                print(f"Load JSON {path} error: {e}")
            return None

    def save_json(self,path,data):
        try:
            with open(path,'w') as f: json.dump(data,f,indent=2)
        except Exception as e:
            self.log_error(f"Save JSON {path} error: {e}")

    # --- Profile Management ---
    def on_profile_select(self,event=None):
        self.load_profile_fields(self.profile_var.get())

    def load_profile_fields(self,name):
        p = self.profiles.get(name,{})
        self.url.set(p.get('url',''))
        self.sec_var.set(p.get('security','NoSecurity'))
        self.user_var.set(p.get('user',''))
        self.pass_var.set('')

    def add_profile(self):
        name = simpledialog.askstring('Profile Name','Enter name:')
        if not name or name in self.profiles: return
        u = self.user_var.get().strip()
        self.profiles[name]={'url':self.url.get(),
                             'security':self.sec_var.get(),
                             'user':u}
        self.save_json(PROFILES_FILE,self.profiles)
        self.profile_cb['values']=list(self.profiles.keys())
        self.profile_var.set(name)

    def edit_profile(self):
        name=self.profile_var.get(); 
        if not name: return
        u,p=self.user_var.get().strip(),self.pass_var.get().strip()
        if not u or not p:
            messagebox.showwarning('Error','User+pass required'); return
        self.profiles[name]={'url':self.url.get(),
                             'security':self.sec_var.get(),
                             'user':u,'password':p}
        self.save_json(PROFILES_FILE,self.profiles)
        messagebox.showinfo('Saved',f'Profile \"{name}\" updated')

    def delete_profile(self):
        name=self.profile_var.get()
        if name and messagebox.askyesno('Delete',f'Delete {name}?'):
            del self.profiles[name]
            self.save_json(PROFILES_FILE,self.profiles)
            vals=list(self.profiles.keys())
            self.profile_cb['values']=vals
            if vals:
                self.profile_var.set(vals[0])
                self.load_profile_fields(vals[0])
            else:
                self.profile_var.set('')

    # --- Connect / Disconnect ---
    def connect(self):
        u,p=self.user_var.get().strip(),self.pass_var.get().strip()
        if not u or not p:
            messagebox.showwarning('Error','User+pass required'); return
        url=self.url.get().strip()
        if not url:
            messagebox.showwarning('Error','URL required'); return
        try:
            if self.client: self.client.disconnect()
            self.client=Client(url)
            sec=self.sec_var.get()
            if sec!='NoSecurity':
                self.client.set_security_string(
                    'http://opcfoundation.org/UA/SecurityPolicy#'+sec)
            self.client.set_user(u); self.client.set_password(p)
            self.client.connect()
            messagebox.showinfo('OK','Connected'); self.log('Connected to '+url)

            root=self.client.get_objects_node()
            self.tree.delete(*self.tree.get_children())
            self._populate_node(root,'')

            vars=self.find_vars(root)
            self.node_map={nid:node for node,nid in vars}

            prof=self.profile_var.get()
            for nid in self.session.get(prof,[]):
                if self.tree.exists(nid):
                    t=self.tree.item(nid,'text')
                    self.tree.item(nid,text='[x]'+t[3:])
            self.apply_sub()
        except Exception as e:
            self.log_error(f"Connect error: {str(e)}")
            messagebox.showerror('Error',f"Connection failed: {e}")

    def disconnect(self):
        try:
            if self.sub:
                for h in list(self.handles.values()):
                    try: self.sub.unsubscribe(h)
                    except Exception as e: self.log_error(f"Unsub error: {e}")
                self.sub.delete(); self.sub=None
                self.handles.clear(); self.subs.clear()
                self.sub = None
            if self.client:
                self.client.disconnect()
                self.log("Disconnected from server.")
                self.client = None
            prof=self.profile_var.get()
            self.session[prof]=list(self.values.keys())
            self.save_json(SESSION_FILE,self.session)
            messagebox.showinfo('Info','Disconnected + session saved')
        except Exception as e:
            self.log_error(f"Disconnect error: {str(e)}")
            messagebox.showerror('Error',f"Disconnect error: {e}")

    # --- Namespace Discovery ---
    def find_vars(self,ua_node,depth=0,max_depth=5):
        res=[]
        if depth>max_depth: return res
        from opcua import ua as ua_mod
        try: kids=ua_node.get_children()
        except Exception as e:
            self.log_error(f"find_vars children error: {e}")
            return res
        for c in kids:
            try:cls=c.get_node_class()
            except Exception as e:
                self.log_error(f"find_vars get_node_class error: {e}")
                continue
            if cls==ua_mod.NodeClass.Variable:
                try:
                    nm=c.get_browse_name().Name; nid=c.nodeid.to_string()
                    dtid=c.get_data_type()
                    dt_nm=self.client.get_node(dtid).get_browse_name().Name
                    self.node_cache[nid]=(nm,dt_nm)
                    res.append((c,nid))
                except Exception as e:
                    self.log_error(f"find_vars variable error: {e}")
            elif cls==ua_mod.NodeClass.Object:
                res.extend(self.find_vars(c,depth+1,max_depth))
        return res

    # --- Subscription Management (SAFE) ---
    def apply_sub(self):
        if not self.sub:
            self.handler=GuiHandler(self.queue,self.node_cache,self.log)
            self.sub=self.client.create_subscription(500,self.handler)
        errors = []
        for nid,node in self.node_map.items():
            if not self.tree.exists(nid):
                continue
            try:
                cls = node.get_node_class()
                if cls != ua.NodeClass.Variable:
                    continue
            except Exception as e:
                self.log_error(f"Subscription node class error for {nid}: {e}")
                continue
            try:
                if self.tree.item(nid,'text').startswith('[x]') and nid not in self.subs:
                    h=self.sub.subscribe_data_change(node)
                    self.handles[nid]=h; self.subs.add(nid)
                    nm,dt=self.node_cache[nid]
                    try:
                        dv = node.get_data_value()
                        val = dv.Value.Value
                        server_ts = dv.ServerTimestamp or ''
                        source_ts = dv.SourceTimestamp or ''
                    except Exception:
                        val = ''
                        server_ts = ''
                        source_ts = ''
                    self.values[nid]=(nm,nid,dt,val,server_ts,source_ts)
            except BadAttributeIdInvalid as e:
                self.log_error(f"Cannot subscribe {nid}: {e}")
                errors.append(nid)
                continue
            except UaStatusCodeError as e:
                self.log_error(f"StatusCode error on subscribe {nid}: {e}")
                errors.append(nid)
                continue
            except Exception as e:
                self.log_error(f"General subscribe error for {nid}: {e}")
                errors.append(nid)
                continue
        self.update_table()
        if errors:
            messagebox.showwarning("Warning", f"Skipped {len(errors)} unsupported nodes")
        else:
            messagebox.showinfo('Info','Subscriptions applied')

    def remove_sel(self):
        for nid in self.tbl.selection():
            if nid in self.subs:
                try: self.sub.unsubscribe(self.handles[nid])
                except Exception as e: self.log_error(f"Unsub error: {e}")
                del self.handles[nid]; self.subs.remove(nid)
                self.values.pop(nid,None)
                t=self.tree.item(nid,'text')
                if t.startswith('[x]'):
                    self.tree.item(nid,text='[ ]'+t[3:])
        self.update_table()
        messagebox.showinfo('Info','Unsubscribed')

    def clear_all(self):
        if self.sub:
            for h in list(self.handles.values()):
                try: self.sub.unsubscribe(h)
                except Exception as e: self.log_error(f"Clear unsub error: {e}")
            self.sub.delete()
        self.sub=None; self.handles.clear(); self.subs.clear(); self.values.clear()
        for iid in self.tree.get_children(''):
            t=self.tree.item(iid,'text')
            if t.startswith('[x]'):
                self.tree.item(iid,text='[ ]'+t[3:])
        self.update_table()
        messagebox.showinfo('Info','All unsubscribed')

    # --- Table Update & Sorting ---
    def update_table(self,*args):
        term=self.filter_var.get().strip(); pat=None
        if term.startswith('/') and term.endswith('/') and len(term)>2:
            try: pat=re.compile(term[1:-1],re.IGNORECASE)
            except: pat=None
        elif term:
            pat=re.compile(re.escape(term),re.IGNORECASE)
        self.tbl.delete(*self.tbl.get_children())
        for nid,(nm,nid2,dt,val,svr,wt) in self.values.items():
            txt=f"{nm} {dt} {val} {svr} {wt}"
            if pat and not pat.search(txt): continue
            self.tbl.insert('', 'end', iid=nid, values=(nm,nid2,dt,val,svr,wt))

    def sort_col(self,col,rev):
        data=[(self.tbl.set(k,col),k) for k in self.tbl.get_children('')]
        try: data.sort(key=lambda t:float(t[0]),reverse=rev)
        except: data.sort(reverse=rev)
        for i,(_,k) in enumerate(data): self.tbl.move(k,'',i)
        self.tbl.heading(col,command=lambda c=col:self.sort_col(c,not rev))

    def proc(self):
        while not self.queue.empty():
            item = self.queue.get()
            if len(item) == 5:
                nid, name, val, source_ts, server_ts = item
            # Lookup dt (data type)
                dt = self.node_cache.get(nid, ('', ''))[1]
                self.values[nid] = (name, nid, dt, val, source_ts, server_ts)
                self.update_table()
    # Live server health check (every second)
        if self.client:
            try:
            # Try to read the server's time (just as a "ping")
                self.client.get_server_node().get_child(["0:ServerStatus", "0:CurrentTime"]).get_value()
                self.update_status_bar("Connected", "green")
            except Exception:
                self.update_status_bar("Disconnected", "red")
        else:
            self.update_status_bar("Disconnected", "red")
        self.after(1000, self.proc)

    def format_value(self, val):
        if isinstance(val, (list, tuple)):
            return ', '.join(str(v) for v in val)
        elif isinstance(val, dict):
            return json.dumps(val, indent=2)
        else:
            return str(val)

    def on_table_double_click(self, event):
        sels = self.tbl.selection()
        if not sels:
            return
        nid = sels[0]
        nm, nid2, dt, val, svr, wt = self.values[nid]
        try:
            node = self.node_map[nid]
            raw_val = node.get_value()
        except Exception:
            raw_val = val
        if isinstance(raw_val, (list, tuple)):
            self.show_array_popup(nm, raw_val)
        elif isinstance(raw_val, dict):
            self.show_struct_popup(nm, raw_val)
        else:
            self.write_value()

    def show_array_popup(self, name, arr):
        win = tk.Toplevel(self)
        win.title(f"Array Value for {name}")
        tk.Label(win, text=f"{name} (Length: {len(arr)})").pack()
        lst = tk.Listbox(win, width=40)
        lst.pack(fill=tk.BOTH, expand=True)
        for i, val in enumerate(arr):
            lst.insert(tk.END, f"[{i}]: {val}")
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=5)

    def show_struct_popup(self, name, struct):
        win = tk.Toplevel(self)
        win.title(f"Structured Value for {name}")
        txt = tk.Text(win, width=60, height=15)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert("end", json.dumps(struct, indent=2))
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=5)

    # --- Write Back ---
    def write_value(self):
        sels=self.tbl.selection()
        if not sels:
            messagebox.showwarning('Error','Select row'); return
        nid=sels[0]; nm,nid2,dt,val,svr,wt=self.values[nid]
        try:
            node = self.node_map[nid]
            raw_val = node.get_value()
        except Exception:
            raw_val = val
        if isinstance(raw_val, (list, tuple)):
            newstr = simpledialog.askstring('Write Array Value', f'Enter comma-separated values for {nm}:')
            if newstr is None: return
            try:
                if raw_val:
                    base_type = type(raw_val[0])
                    new = [base_type(v.strip()) for v in newstr.split(",")]
                    vt = ua.VariantType.Double if base_type is float else ua.VariantType.Int64
                else:
                    new = [v.strip() for v in newstr.split(",")]
                    vt = ua.VariantType.String
            except Exception as e:
                messagebox.showerror('Error', f'Invalid array: {e}')
                return
            try:
                v = ua.Variant(new, vt)
                node.set_value(v)
                nws = time.strftime('%Y-%m-%d %H:%M:%S')
                self.values[nid]=(nm,nid,dt,self.format_value(new),svr,nws)
                self.update_table()
                self.log(f"Wrote value {new} to {nm} ({nid})")
                messagebox.showinfo('Success','Written')
            except Exception as e:
                self.log_error(f"Write error: {e}")
                messagebox.showerror('Error', str(e))
            return
        if dt.lower()=='boolean':
            win=tk.Toplevel(self); win.title(f'Write {nm}')
            var=tk.BooleanVar(value=bool(val))
            ttk.Checkbutton(win,text=nm,variable=var).pack(padx=20,pady=10)
            def ok():
                new=var.get(); v=ua.Variant(new,ua.VariantType.Boolean)
                self.node_map[nid].set_value(v)
                nws=time.strftime('%Y-%m-%d %H:%M:%S')
                self.values[nid]=(nm,nid,dt,new,svr,nws)
                self.update_table(); win.destroy()
            ttk.Button(win,text='OK',command=ok).pack(pady=5)
            return
        newstr=simpledialog.askstring('Write Value',f'Enter new value for {nm}:')
        if newstr is None: return
        try:
            if dt.lower().startswith('int'):
                new=int(newstr); vt=ua.VariantType.Int64
            elif dt.lower().startswith(('float','double')):
                new=float(newstr); vt=ua.VariantType.Double
            else:
                new=newstr; vt=ua.VariantType.String
        except Exception as e:
            messagebox.showerror('Error',f'Invalid: {e}'); return
        try:
            v=ua.Variant(new,vt)
            self.node_map[nid].set_value(v)
            nws=time.strftime('%Y-%m-%d %H:%M:%S')
            self.values[nid]=(nm,nid,dt,new,svr,nws)
            self.update_table(); messagebox.showinfo('Success','Written')
        except Exception as e:
            self.log_error(f"Write error: {e}")
            messagebox.showerror('Error',str(e))

    def on_exit(self):
        self.disconnect()
        self.save_prefs()
        self.destroy()


    def update_status_bar(self, status, color='black'):
        self.status_var.set(status)
        self.status_label.config(foreground=color)

    def show_server_info(self):
        if not self.client:
            messagebox.showinfo("Info", "Not connected to any server!")
            return
        info = ""
        try:
            srv = self.client.get_server_node()
        # Try to get product name
            try:
                buildinfo = srv.get_child(["0:ServerStatus", "0:BuildInfo"])
                product = buildinfo.get_child("0:ProductName").get_value()
                info += f"App Name: {product}\n"
            except Exception:
                info += "App Name: <not available>\n"
        # Try to get ApplicationUri
            try:
                uri = buildinfo.get_child("0:ApplicationUri").get_value()
                info += f"App URI: {uri}\n"
            except Exception:
                info += "App URI: <not available>\n"
        # Endpoint & security from client settings
            info += f"Endpoint: {self.url.get()}\n"
            info += f"Security: {self.sec_var.get()}\n"
        # Try to get namespaces
            try:
                nsarray = self.client.get_namespace_array()
                info += "Namespaces:\n" + '\n'.join(nsarray) + "\n"
            except Exception:
                info += "Namespaces: <not available>\n"
        except Exception as e:
            info += f"Server node error: {e}\n"
        messagebox.showinfo("Server Information", info)
        self.log("Server info shown")

    

if __name__=='__main__':
    OPCUAGuiApp().mainloop()







































