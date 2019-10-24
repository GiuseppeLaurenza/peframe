import json


from peframe import analyze

path = "/home/giuseppe/binaries/apt/121320414d091508ac397044495d0d9c"
prova = analyze(path)
print(prova)

from peframe_bck.peframe import analyze_json
with open("/tmp/2.json","r") as infile:
    prova2 = json.load(infile)

print(prova2)

