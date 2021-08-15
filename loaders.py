def loadnmapservices():
    fileName = '/usr/local/share/nmap/nmap-services'  # Replace with path on your system
    with open(fileName) as f:
        lines = f.readlines()
        f.close()
    servicelist = {}
    for line in lines:
        if line[0] != '#':
            servname = line.split('\t')[0]
            if servname != 'unknown':
                portproto = line.split('\t')[1]
                servicelist[portproto] = servname
    return servicelist
