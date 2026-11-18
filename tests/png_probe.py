import json, sys
from PIL import Image
im = Image.open(sys.argv[1])
im.load()  # force a full decode
print(json.dumps({"size": list(im.size), "mode": im.mode, "format": im.format}))
