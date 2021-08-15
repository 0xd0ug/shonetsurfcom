import csv
import random
import statistics
from multiprocessing.pool import Pool

import Levenshtein
import numpy as np
from sklearn import metrics
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics import pairwise_distances

from attackSurfaceNode import Service
from loaders import loadnmapservices


class AttackSurface:

    @staticmethod
    def statsHeader():
        return "Infile,Linkage,DistThreshold,PortWeight,Services,Clusters,Outliers,MinLength,MaxLength,Mean,Q1,Median,Q3,Davies-Bouldin,Calinski-Harabasz,Silhouette,Non-Hom Clusters"

    def stats(self, threshold, linkage, infile):
        servnonhom = 0
        quantiles = statistics.quantiles(self.clusterlengths, n=4)
        sil = metrics.silhouette_score(self.sims, self.labels)
        db = metrics.davies_bouldin_score(self.sims, self.labels)
        ch = metrics.calinski_harabasz_score(self.sims, self.labels)
        for x in self.clusters:
            protolist = []
            for node in x:
                protolist.append(self.nodes[node].service)
            if len(protolist) != protolist.count(protolist[0]):
                servnonhom += 1

        x = '{},{},{:.3f},{:.2f},{},{},{},{},{},{:.2f},{},{},{},{:.2f},{:.2f},{:.2f},{}'.format(infile, linkage,
                                                                                                threshold,
                                                                                                self.portWeight,
                                                                                                len(self.nodes),
                                                                                                len(self.clusters),
                                                                                                len(self.outliers),
                                                                                                min(self.clusterlengths),
                                                                                                max(self.clusterlengths),
                                                                                                statistics.mean(
                                                                                                    self.clusterlengths),
                                                                                                quantiles[0],
                                                                                                quantiles[1],
                                                                                                quantiles[2],
                                                                                                db, ch, sil, servnonhom)
        return x

    def __str__(self):
        z = ("Cluster,Node,IP,Port,Service,Banner\n")
        for x in range(len(self.clusters)):
            for y in self.clusters[x]:
                z += str(x) + ',' + str(y) + ',' + str(self.nodes[y]) + '\n'  # Prints each service one per line
        for y in self.outliers:
            z += '-1,' + str(y) + ',' + str(self.nodes[y]) + '\n'
        return z

    def singleSim(self, x, y):
        return self.shortSims[x.servindex, y.servindex]

    def simAffinity(self, X):
        return pairwise_distances(X, metric=self.singleSim)

    def simMulti(self, a):
        n = len(self.nodes)
        Sim = np.ones((n,), dtype=np.float32)
        x = self.nodes[a].servindex
        for b in range(n):
            Sim[b] = self.shortSims[x, self.nodes[b].servindex]
        return Sim

    def __init__(self):
        self.nodes = []
        self.services = []
        self.portWeight = 0.5

    def shortSim(self):
        self.shortSims = np.ones((len(self.services), len(self.services)), dtype=np.float32)
        for a in range(len(self.services)):
            for b in range(len(self.services)):
                self.shortSims[a][b] = 1 - (Levenshtein.jaro(self.services[a][0], self.services[b][0]) *
                                            self.portWeight + Levenshtein.jaro(self.services[a][1], self.services[b][1])
                                            * (1 - self.portWeight))

    def sim(self):
        pool = Pool(8)
        size = range(len(self.nodes))
        self.sims = np.array(pool.map(self.simMulti, size))
        pool.close()
        pool.join()

    def clustercomp(self):
        self.compClusters = []
        for cluster in self.clusters:
            self.compClusters.append({})
            currClusterNum = len(self.compClusters) - 1
            for nodeNum in cluster:
                nodeInfo = (self.nodes[nodeNum].port, self.nodes[nodeNum].service, self.nodes[nodeNum].banner)
                if nodeInfo in self.compClusters[currClusterNum]:
                    self.compClusters[currClusterNum][nodeInfo] += 1
                else:
                    self.compClusters[currClusterNum][nodeInfo] = 1
        z = "Cluster,Count,Port,Service,Banner\n"
        for x in range(len(self.compClusters)):
            for y in self.compClusters[x]:
                z += str(x) + "," + str(self.compClusters[x][y]) + "," + str(y[0]) + "," + y[1] + "," + y[2] + "\n"
        for y in self.outliers:
            z += '-1,1,' + str(self.nodes[y].port) + ',' + self.nodes[y].service + ',' + self.nodes[y].banner + '\n'
        return z

    def getServFromCluster(self, e):
        # Sort function for clusters
        return self.nodes[e[0]].service

    def getServFromOutlier(self, e):
        # Sort function for outliers
        return self.nodes[e].service

    def cluster(self, linkage='complete', dt=.1):
        clustering = AgglomerativeClustering(affinity='precomputed', linkage=linkage, n_clusters=None,
                                             distance_threshold=dt)
        self.clusters = []
        self.clusterlengths = []
        self.outliers = []
        self.labels = clustering.fit_predict(self.sims)
        for x in range(max(self.labels) + 1):
            self.clusters.append([])

        for x in range(len(self.labels)):
            self.clusters[self.labels[x]].append(x)

        for x in self.clusters:
            if len(x) == 1:
                self.outliers.append(x[0])
        self.clusters[:] = [x for x in self.clusters if len(x) > 1]
        self.clusters.sort(key=self.getServFromCluster)
        for x in self.clusters:
            self.clusterlengths.append(len(x))
        clusters = []
        self.minSims = []
        for cluster in self.clusters:
            z = []
            for x in range(len(cluster)):
                zz = []
                for y in range(x):
                    zz.append(self.sims[x][y])
            z.append(min(zz))
        self.outliers.sort(key=self.getServFromOutlier)

    def loadshodanfile(self, fileName: str):
        # Loads CSV output from Shodan or from recon-ng tool
        random.seed()
        servicelist = loadnmapservices()
        # Read the input
        file = fileName
        with open(file) as f:
            recon = csv.DictReader(f)
            count = 0
            dupe = 0
            for row in recon:
                ip = row['IP']
                port = row['Port']
                proto = 'tcp'
                banner = str(row['Banner']).split('\n')[0]
                portproto = port + "/" + proto
                if portproto in servicelist:
                    service = servicelist[portproto]
                else:
                    service = ''
                if (service, banner) not in self.services:
                    self.services.append((service, banner))
                else:
                    dupe += 1
                servindex = self.services.index((service, banner))
                self.nodes.append(Service(ip, int(port), service, banner, servindex))
                count += 1
        random.shuffle(self.nodes)
