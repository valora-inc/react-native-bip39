readFile = open("spanish.txt", 'r')
writeFile= open("es.json","w+")
lines = readFile.readlines()

writeFile.write("[\n")
for word in lines:
  writeFile.write("\""+word.replace("\n","")+"\",\n")
writeFile.write("]")
writeFile.close()
