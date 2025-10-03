from kivy.app import App
from kivy.lang import Builder
from ui.view import MainUI


class NmapKivyApp(App):
    def build(self):
        Builder.load_file("nmap.kv")
        return MainUI()


if __name__ == '__main__':
    NmapKivyApp().run()
