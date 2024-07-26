import customtkinter as ctk
from tkinter import messagebox 
from tkinter import *
import requests
import tkintermapview

iaddress=None

class MyApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("IP Explorer")
        self.geometry("700x500")
        self.iconbitmap(r'C:\Users\Akash\Desktop\IpExplorer\logo.ico')
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        main_frame = ctk.CTkFrame(self, bg_color="#2d2d30" )
        main_frame.pack(side="top", fill="both", expand=True)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        page_frames = {}
        
        for Page in (HomePage, mapip, abuseipdb, ipgeo):
            page_name = Page.__name__
            frame = Page(parent=main_frame, controller=self)
            page_frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        
        self.page_frames = page_frames

        self.show_page("HomePage")
        
        self.create_navbar()
        
    
    def create_navbar(self):
        navbar_frame = ctk.CTkFrame(self, fg_color= "#2d2d30" )
        navbar_frame.pack(side="top", fill="x")
        
        navbar_buttons = [
            ("Home", "HomePage"),
            ("Map (IP-API)", "mapip"),
            ("AbuseIPdb Lookup", "abuseipdb"),
            ("IpGeolocation.io Lookup", "ipgeo")
        ]
        
        for label, page_name in navbar_buttons:
            button = ctk.CTkButton(navbar_frame, text=label, command=lambda page_name=page_name: self.show_page(page_name), width=100,height=25,font=("Courier",12))
            button.pack(side="left", padx=5, pady=5)
            
    
    def show_page(self, page_name):
        page = self.page_frames[page_name]
        page.tkraise()

        if hasattr(page, 'update_page'):
            page.update_page()

class HomePage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
       
        label = ctk.CTkLabel(self, text="GET IP INFORMATION USING IPINFO.IO")
        label.pack(side="top", fill="x", pady=10)
        
        ctk.CTkLabel(self, text="Enter IP Address:").pack(pady=5)
        self.ip_entry = ctk.CTkEntry(self, width=300)
        self.ip_entry.pack(pady=5)
        
        trace_button = ctk.CTkButton(self, text="Get Info", command=self.trace_ip)
        trace_button.pack(pady=5)
        
        self.result_text = ctk.CTkTextbox(self, height=200, width=400)
        self.result_text.pack(pady=5)
        self.result_text.configure(state="disabled")
    
    def trace_ip(self):
        
        
        global iaddress
        ip_address = self.ip_entry.get()
        iaddress= ip_address

        if not ip_address:
            messagebox.showerror("Error", "Please enter an IP address")
            return
        
        if ip_address.startswith("192"):
            self.result_text.configure(state="normal")
            self.result_text.delete(1.0, "end")
            self.result_text.insert("end", "It is a private IP address!!")
            self.result_text.configure(state="disabled")
            return
        
        try:
            response = requests.get(f"https://ipinfo.io/{ip_address}/json")
            response.raise_for_status()
            data = response.json()
            
            info = (
                f"IP Address: {data.get('ip')}\n"
                f"Hostname: {data.get('hostname')}\n"
                f"City: {data.get('city')}\n"
                f"Region: {data.get('region')}\n"
                f"Country: {data.get('country')}\n"
                f"Postal Code: {data.get('postal')}\n"
                f"Location: {data.get('loc')}\n"
                f"ISP: {data.get('org')}\n"
               f"VPN: {data.get('vpn')}\n"
                f"Proxy: {data.get('proxy')}\n"
                f"Threat Level: {data.get('threat_level')}\n"
            )
            self.result_text.configure(state="normal")
            self.result_text.delete(1.0, "end")
            self.result_text.insert("end", info)
            self.result_text.configure(state="disabled")
            
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Unable to get data: {e}")

        
            

class mapip(ctk.CTkFrame):
    def __init__(self, parent, controller): 
        super().__init__(parent)
        self.controller = controller
      
        self.map_frame = ctk.CTkFrame(self)
        self.map_frame.pack(fill='both')
        
        self.map_widget = tkintermapview.TkinterMapView(self.map_frame, height=500,width=500, corner_radius=0)
        self.map_widget.pack(fill='both')
       
       

    def update_page(self):
        if iaddress:
            self.trace_ip(iaddress)    
        else:
             messagebox.showerror("Error", "No IP address provided in Home Page")

    def trace_ip(self, ipTotrace ):
        
        
        location = self.get_ip_location(ipTotrace)
        if location:
            latitude, longitude, city = location
            self.map_widget.set_position(latitude, longitude)
            self.map_widget.set_marker(latitude, longitude, text=city)
            

    def get_ip_location(self, ip):
        try:
           
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            if data['status'] == 'success':
                return data['lat'], data['lon'], data['city']
            else:
                messagebox.showerror("Error", "Failed to retrieve location data.")
                return None
        except Exception as e:
            messagebox.showerror("Error", f"Error occurred: {e}")
            return None


class abuseipdb(ctk.CTkFrame):
     def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        label = ctk.CTkLabel(self, text="Check IP Reputation using AbuseIPDB")
        label.pack(side="top", fill="x", pady=10)

        self.reputation_button = ctk.CTkButton(self, text="Check Reputation", command=self.check_reputation)
        self.reputation_button.pack(pady=10)

        self.result_text = ctk.CTkTextbox(self, height=350, width=400)
        self.result_text.pack(pady=10)
        
        self.result_text.configure(state="disabled")

     

     def check_reputation(self):
        if iaddress:
            self.get_ip_reputation(iaddress)

     def get_ip_reputation(self, ip_address):
        api_key = "a489a3225c01e9cc915f3e5a268e9d2d9fe8e6255def0c16337b60ef33980c73d5d982b98756c923"
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"

        headers = {
            "Accept": "application/json",
            "Key": api_key
        }

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()

            info = (
                f"IP Address: {data['data']['ipAddress']}\n"
                f"Is Public: {data['data']['isPublic']}\n"
                f"IP Version: {data['data']['ipVersion']}\n"
                f"Is Whitelisted: {data['data']['isWhitelisted']}\n"
                f"Abuse Confidence Score: {data['data']['abuseConfidenceScore']}\n"
                f"Country Code: {data['data']['countryCode']}\n"
                f"Usage Type: {data['data']['usageType']}\n"
                f"ISP: {data['data']['isp']}\n"
                f"Domain: {data['data']['domain']}\n"
                f"Total Reports: {data['data']['totalReports']}\n"
                f"Last Reported At: {data['data']['lastReportedAt']}\n"
                
            )

            self.result_text.configure(state="normal")
            self.result_text.delete(1.0, "end")
            self.result_text.insert("end", info)
            self.result_text.configure(state="disabled")

        except requests.RequestException as e:
            messagebox.showerror("Error", f"Unable to get data: {e}")


class ipgeo(ctk.CTkFrame):
      def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.label = ctk.CTkLabel(self, text="IP Geolocation using IPGeolocation.io API", font=("Helvetica", 14, "bold"))
        self.label.pack(side="top", fill="x", pady=10)
        self.search_button = ctk.CTkButton(self, text="Search", command=self.get_ip_info)
        self.search_button.pack(pady=5)

        self.result_text = ctk.CTkTextbox(self, height=350, width=400)
        self.result_text.pack(pady=10)
        self.result_text.configure(state="disabled")

      def get_ip_info(self):
        ip_address = iaddress
        if not iaddress:
            messagebox.showerror("Error", "Please enter an IP address")
            return
        
        try:
            response = requests.get(f"https://api.ipgeolocation.io/ipgeo?apiKey=9a5d366521be4ee897a95e1ed05fa80e&ip={ip_address}")
            response.raise_for_status()
            data = response.json()

            info = (
                f"IP Address: {data.get('ip')}\n"
                f"Country: {data.get('country_name')}\n"
                f"Region: {data.get('region')}\n"
                f"City: {data.get('city')}\n"
                f"District: {data.get('district')}\n"
                f"State Provience: {data.get('state_prov')}\n"
                f"Calling Code: {data.get('calling_code')}\n"
                f"Languages: {data.get('languages')}\n"
                f"ZIP Code: {data.get('zipcode')}\n"
                f"Latitude: {data.get('latitude')}\n"
                f"Longitude: {data.get('longitude')}\n"
                f"Timezone: {data.get('timezone')}\n"
                f"ISP: {data.get('isp')}\n"
                f"Domain: {data.get('organization')}\n"
                f"Connection Type: {data.get('connection_type')}\n"
                
                
            )

            self.result_text.configure(state="normal")
            self.result_text.delete(1.0, "end")
            self.result_text.insert("end", info)
            self.result_text.configure(state="disabled")

        except requests.RequestException as e:
            messagebox.showerror("Error", f"Unable to get data: {e}")




if __name__ == "__main__":
    app = MyApp()
    app.mainloop()
