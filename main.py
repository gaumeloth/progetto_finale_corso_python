#!/usr/bin/env python3
from ui import MainUI
from kivy.app import App
from kivy.lang import Builder

# carichiamo il file kv esterno (nome: nmap.kv)
Builder.load_file("nmap.kv")

# Importiamo MainUI dalla versione modularizzata


class NmapKivyApp(App):
    def build(self):
        return MainUI()


if __name__ == '__main__':
    NmapKivyApp().run()
