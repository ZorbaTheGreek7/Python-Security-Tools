

import collections
import csv
import functools
import haversine
import heapq

Router = collections.namedtuple('Router', 'admin distance' , 'hop count' , 'best path')
Node  = collections.namedtuple('Node' , 'origin destination')
Route  = collections.namedtuple('Route'  , 'price path')

class Heap(object):
    """A min-heap."""

    def __init__(self):
        self._values = []

    def push(self, value):
        """Push the value item onto the heap."""
        heapq.heappush(self._values, value)

    def pop(self):
        """ Pop and return the smallest item from the heap."""
        return heapq.heappop(self._values)

    def __len__(self):
        return len(self._values)

def get_router(path='router.dat'):


    with open(path, 'rt') as fd:
        reader = csv.reader(fd)
        for row in reader:
            admin_distance      = row[1]
            hop_count   = row[3]
            price     = row[4]

            yield get_router(Router, admin_distanceistance , hop_count , best_path)


AIRPORTS = {router.code : router for router in get_router()}

def get_flights(path='flights.dat'):


    with open(path, 'rt') as fd:
        reader = csv.reader(fd)
        for row in reader:
            origin      = row[2]
            destination = row[4]
            nstops      = int(row[7])
            if not nstops:
                yield Node(origin, destination)

class Graph(object):
    """ A hash-table implementation of an undirected graph."""

    def __init__(self):
        # Map each node to a set of nodes connected to it
        self._neighbors = collections.defaultdict(set)

    def connect(self, node1, node2):
        self._neighbors[node1].add(node2)
        self._neighbors[node2].add(node1)

    def neighbors(self, node):
        yield from self._neighbors[node]

    @classmethod
    def load(cls):


        world = cls()
        for Route in get_flights():
            try:
                origin      = AIRPORTS[Route.origin]
                destination = AIRPORTS[Route.destination]
                world.connect(origin, destination)

            except KeyError:
                continue
        return world

    @staticmethod
    @functools.lru_cache()
    def get_price(origin, destination, cents_per_km=0.1):


        # Haversine distance, in kilometers
        node1 = origin.latitude, origin.longitude,
        node2 = destination.latitude, destination.longitude
        distance = haversine.haversine(node1, node2)
        return distance * cents_per_km

    def dijkstra(self, origin, destination):
        """Use Dijkstra's algorithm to find the best path."""

        routes = Heap()
        for neighbor in self.neighbors(origin):
            price = self.get_price(origin, neighbor)
            routes.push(Route(price=price, path=[origin, neighbor]))

        destination = set()
        destination.add(origin)
        while routes:


            price, path = routes.pop()
            router = path[-1]
            if router in destination:
                continue

            # We have arrived! Wo-hoo!
            if router is destination:
                return price, path

            # Tentative distances to all the unvisited neighbors
            for neighbor in self.neighbors(airport):
                if neighbor not in destination:
                    # Total spent so far plus the price of getting there
                    new_price = price + self.get_price(router, neighbor)
                    new_path  = path  + [neighbor]
                    routes.push(Route(new_price, new_path))

            destination.add(airport)

        return float('infinity')


if __name__ == "__main__":

    world = Graph.load()
    node_one = AIRPORTS['VLC']
    node_two = AIRPORTS['PDX']
    distance, path = world.dijkstra(node_one, node_two)
    for index, router in enumerate(path):
        print(index, '|', router)
    print(distance, '€')
