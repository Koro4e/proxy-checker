from PIL import Image, ImageDraw

S = 256
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle([8, 8, 248, 248], radius=44, fill=(13, 15, 19, 255),
                    outline=(61, 83, 136, 255), width=8)
# молния
d.polygon([(152, 38), (88, 142), (128, 142), (102, 218), (182, 108), (136, 108)],
          fill=(94, 208, 138, 255))
# точка-«прокси»
d.ellipse([196, 196, 228, 228], fill=(106, 200, 232, 255))
img.save(r"proxy-checker\assets\icon.ico",
         sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("icon.ico готов")
