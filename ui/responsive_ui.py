import tkinter as tk
from config import CONFIG

class ResponsiveUIHelper:
    def __init__(self, root):
        self.root = root
        self.current_width = 0
        self.current_height = 0
        self.scale_factor = 1.0
        self.font_cache = {}
        
    def calculate_font_size(self, base_size, scale_factor=None):
        if scale_factor is None:
            scale_factor = self.scale_factor
        
        size = int(base_size * scale_factor)
        return max(CONFIG["ui"]["min_font_size"], 
                   min(CONFIG["ui"]["max_font_size"], size))
    
    def get_scaled_font(self, family, base_size, weight="normal"):
        key = (family, base_size, weight, self.scale_factor)
        if key not in self.font_cache:
            size = self.calculate_font_size(base_size)
            self.font_cache[key] = (family, size, weight)
        return self.font_cache[key]
    
    def update_scale_factor(self, width, height):
        self.current_width = width
        self.current_height = height
        base_width = CONFIG["ui"]["responsive_threshold"]
        if width < base_width:
            self.scale_factor = max(0.8, width / base_width)
        else:
            self.scale_factor = min(1.3, 1.0 + (width - base_width) / (base_width * 2))
    
    def configure_responsive_column_widths(self, treeview, column_configs):
        total_width = self.current_width - 50
        if total_width < 400:
            total_width = 400
        
        total_ratio = sum(config.get("ratio", 1) for config in column_configs.values())
        
        for col, config in column_configs.items():
            ratio = config.get("ratio", 1)
            min_width = config.get("min_width", CONFIG["ui"]["column_min_width"])
            width = max(min_width, int((total_width * ratio) / total_ratio))
            
            try:
                treeview.column(col, width=width)
            except tk.TclError:
                pass