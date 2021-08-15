#!/usr/bin/env python3
import os
from datetime import datetime
from time import time

from attackSurface import AttackSurface

if __name__ == '__main__':

    start_time = time()
    outDir = "output" + datetime.now().strftime("%Y%m%d%H%M")
    if not (os.path.exists(outDir)):
        os.makedirs(outDir)
    statsOut = open(outDir + "/stats.csv", "w")
    print(AttackSurface.statsHeader())
    statsOut.write(AttackSurface.statsHeader() + '\n')
    for infile in ["university.csv"]:
        surface = AttackSurface()
        surface.loadshodanfile(infile)

        for portWeight in [0.75]:
            surface.portWeight = portWeight
            surface.shortSim()
            surface.sim()

            for threshenum in [0.028]:
                # for linkage in ['complete', 'average', 'single']:
                for linkage in ['average']:
                    threshold = threshenum
                    surface.cluster(dt=threshold, linkage=linkage)
                    print(surface.stats(threshold=threshold, infile=infile, linkage=linkage))
                    statsOut.write(surface.stats(threshold=threshold, infile=infile, linkage=linkage) + '\n')
                    baseName = infile.split(".")[0] + '_' + str(int(portWeight * 100)) + '_' \
                               + "{:.3f}".format(threshold) + '_' + str(linkage) + '.csv'
                    outFile = outDir + '/' + baseName
                    with open(outFile, "w") as f:
                        f.write(str(surface))
                        f.close()
                    outFile = outDir + '/' + "comp_" + baseName
                    with open(outFile, "w") as f:
                        f.write(surface.clustercomp())
                        f.close()
        del surface
    statsOut.close()
    print("--- %s seconds ---" % (time() - start_time))
