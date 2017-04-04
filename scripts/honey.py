import argparse
import os
import random
from PIL import Image
from PIL import ImageDraw

HONEY_TXT = "a.txt"
HONEY_HTML = "a.html"
HONEY_PIC = "a.png"

def write_honey_image(path):
    FONT_SIZE = 80
    bgcolor = 0xff0000
    im = Image.new('RGB', (100, 100), bgcolor)
    im.save(path, format='png')

def write_honey_txt(path):
    data = ["hello world"] * 10
    data = " ".join(data)
    with open(path, 'w') as f:
        f.write(data)

def write_honey_html(path):
    with open(path, 'w') as f:
        f.write("<html><head></head><body><h1>Hello World</h1></body></html>")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create honey files")
    parser.add_argument("--start",default=".", help="Root to where to start placing honey files")
    args = parser.parse_args()

    start_dir = os.path.abspath(args.start)
    print start_dir
    for root, dirs, files in os.walk(start_dir):
        try:
            txt = os.path.join(root, HONEY_TXT)
            write_honey_txt(txt)
            print "Create text file at {}".format(txt)
            pic = os.path.join(root, HONEY_PIC)
            write_honey_image(pic)
            print "Create image at {}".format(pic)
            html = os.path.join(root, HONEY_HTML)
            write_honey_html(html)
            print "Create HTML at {}".format(html)

        except:
            print "Failed to write to {}".format(root)
