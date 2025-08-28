import tkinter as tk
from tkinter import messagebox
import time
import sys
import threading
from collections import defaultdict

from utils.logger import log
from config import dns_queue, geo_queue
from ui.main_window import NetstatApp
from utils.ip_utils import geo_worker, reverse_dns_worker

def main():
    log("INFO", "🚀 Starting Enhanced Responsive Network Security Monitor")
    try:
        geo_thread = threading.Thread(target=geo_worker, daemon=True)
        geo_thread.start()
        dns_thread = threading.Thread(target=reverse_dns_worker, daemon=True)
        dns_thread.start()

        root = tk.Tk()
        root.configure(bg="#f0f0f0")
        app = NetstatApp(root)

        def on_closing():
            try:
                if app.is_monitoring:
                    app.stop_monitoring()
                    time.sleep(1)
            except Exception as e:
                log("ERROR", f"Error stopping monitoring: {e}")
            try:
                dns_queue.put_nowait((None, None))
                geo_queue.put_nowait((None, None))
            except Exception as e:
                log("ERROR", f"Error stopping worker threads: {e}")
            log("INFO", "🔚 Application shutdown complete")
            root.destroy()
            sys.exit(0)

        root.protocol("WM_DELETE_WINDOW", on_closing)
        log("INFO", "✅ Application initialized successfully. Starting main loop...")
        root.mainloop()

    except Exception as e:
        log("CRITICAL", f"💥 Application startup failed: {e}")
        try:
            messagebox.showerror("Startup Error", f"Failed to start application:\n{str(e)}")
        except:
            pass
        sys.exit(1)

if __name__ == "__main__":
    main()