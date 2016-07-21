# encoding: utf-8

import os
import re
import sys
import struct
import json
import time
import requests
import argparse
import threading
import werkzeug.serving

import pokemon_pb2

from datetime import datetime
import time

from google.protobuf.internal import encoder
from s2sphere import *
from datetime import datetime
from geopy.geocoders import GoogleV3
from geopy.exc import GeocoderTimedOut, GeocoderServiceError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.adapters import ConnectionError
from requests.models import InvalidURL
from transform import *
from math import radians, cos, sin, asin, sqrt
from pymongo import MongoClient

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

API_URL = 'https://pgorelease.nianticlabs.com/plfe/rpc'
LOGIN_URL = 'https://sso.pokemon.com/sso/login?service=https%3A%2F%2Fsso.pokemon.com%2Fsso%2Foauth2.0%2FcallbackAuthorize'
LOGIN_OAUTH = 'https://sso.pokemon.com/sso/oauth2.0/accessToken'
PTC_CLIENT_SECRET = 'w8ScCUXJQc6kXKw8FiOhd8Fixzht18Dq3PEVkUCP5ZPxtgyWsbTvWHFLm2wNY0JR'
GOOGLEMAPS_KEY = "AIzaSyAZzeHhs-8JZ7i18MjFuM35dJHq70n3Hx4"

SESSION = None
def resetSession():
    global SESSION
    SESSION = requests.session()
    SESSION.headers.update({'User-Agent': 'Niantic App'})
    SESSION.verify = False

DEBUG = True
VERBOSE_DEBUG = False  # if you want to write raw request/response to the console

mongoConf = open('mongo.conf', 'r')
conn = MongoClient(mongoConf.read())
mongo = conn.pokemon

# stuff for in-background search thread
search_thread = None

def haversine(lon1, lat1, lon2, lat2):
    """
    Calculate the great circle distance between two points
    on the earth (specified in decimal degrees)
    """
    # convert decimal degrees to radians
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])

    # haversine formula
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    r = 6371 # Radius of earth in kilometers. Use 3956 for miles
    return c * r

def parse_unicode(bytestring):
    decoded_string = bytestring.decode(sys.getfilesystemencoding())
    return decoded_string

def debug(message):
    if DEBUG:
        print('[-] {}'.format(message))

def time_left(ms):
    s = ms / 1000
    m, s = divmod(s, 60)
    h, m = divmod(m, 60)
    return h, m, s


def encode(cellid):
    output = []
    encoder._VarintEncoder()(output.append, cellid)
    return ''.join(output)


def getNeighbors(lat, long):
    origin = CellId.from_lat_lng(LatLng.from_degrees(lat, long)).parent(15)
    walk = [origin.id()]
    # 10 before and 10 after
    next = origin.next()
    prev = origin.prev()
    for i in range(10):
        walk.append(prev.id())
        walk.append(next.id())
        next = next.next()
        prev = prev.prev()
    return walk


def f2i(float):
    return struct.unpack('<Q', struct.pack('<d', float))[0]


def f2h(float):
    return hex(struct.unpack('<Q', struct.pack('<d', float))[0])


def h2f(hex):
    return struct.unpack('<d', struct.pack('<Q', int(hex, 16)))[0]


def retrying_set_location(location_name):
    """
    Continue trying to get co-ords from Google Location until we have them
    :param location_name: string to pass to Location API
    :return: None
    """
    while True:
        try:
            return set_location(location_name)
        except (GeocoderTimedOut, GeocoderServiceError) as e:
            debug("retrying_set_location: geocoder exception ({}), retrying".format(str(e)))
        time.sleep(1.25)


def set_location(location_name):
    geolocator = GoogleV3()
    loc = geolocator.geocode(location_name)
    print('[!] Your given location: {}'.format(loc.address.encode('utf-8')))
    print('[!] lat/long/alt: {} {} {}'.format(loc.latitude, loc.longitude, loc.altitude))
    return [loc.latitude, loc.longitude, loc.altitude]


def set_location_coords(lat, long, alt):
    return [f2i(lat), f2i(long), f2i(alt)]
    # 0x4042bd7c00000000 # f2i(lat)
    # 0xc05e8aae40000000 #f2i(long)


def retrying_api_req(api_endpoint, access_token, lat, long, *args, **kwargs):
    tries = 0
    while tries < 3:
        tries += 1
        try:
            response = api_req(api_endpoint, access_token, lat, long, *args, **kwargs)
            if response:
                return response
            debug("retrying_api_req: api_req returned None, retrying")
        except (InvalidURL, ConnectionError) as e:
            debug("retrying_api_req: request error ({}), retrying".format(str(e)))
        time.sleep(1)
    return None


def api_req(api_endpoint, access_token, lat, long, *args, **kwargs):
    p_req = pokemon_pb2.RequestEnvelop()
    p_req.rpc_id = 1469378659230941192

    p_req.unknown1 = 2

    p_req.latitude, p_req.longitude, p_req.altitude = [lat, long, 0]

    p_req.unknown12 = 989

    if 'useauth' not in kwargs or not kwargs['useauth']:
        p_req.auth.provider = 'ptc'
        p_req.auth.token.contents = access_token
        p_req.auth.token.unknown13 = 14
    else:
        p_req.unknown11.unknown71 = kwargs['useauth'].unknown71
        p_req.unknown11.unknown72 = kwargs['useauth'].unknown72
        p_req.unknown11.unknown73 = kwargs['useauth'].unknown73

    for arg in args:
        p_req.MergeFrom(arg)

    protobuf = p_req.SerializeToString()

    r = SESSION.post(api_endpoint, data=protobuf, verify=False)

    try:
        p_ret = pokemon_pb2.ResponseEnvelop()
        p_ret.ParseFromString(r.content)
    except:
        return None

    if VERBOSE_DEBUG:
        print("REQUEST:")
        print(p_req)
        print("Response:")
        print(p_ret)
        print("\n\n")
    time.sleep(0.51)
    return p_ret


def get_api_endpoint(access_token, lat, long, api=API_URL):
    profile_response = retrying_get_profile(access_token, api, None, lat, long)
    if not hasattr(profile_response, 'api_url'):
        debug('retrying_get_profile: get_profile returned no api_url, retrying')
        return None
    if not len(profile_response.api_url):
        debug('get_api_endpoint: retrying_get_profile returned no-len api_url, retrying')
        return None

    return 'https://%s/rpc' % profile_response.api_url

def retrying_get_profile(access_token, api, useauth, lat, long, *reqq):
    profile_response = None
    tries = 0
    while (not profile_response and tries < 3):
        tries += 1
        profile_response = get_profile(access_token, api, useauth, lat, long, *reqq)
        if not hasattr(profile_response, 'payload'):
            debug('retrying_get_profile: get_profile returned no payload, retrying')
            profile_response = None
            continue
        if not profile_response.payload:
            debug('retrying_get_profile: get_profile returned no-len payload, retrying')
            profile_response = None
    return profile_response

def get_profile(access_token, api, useauth, lat, long, *reqq):
    req = pokemon_pb2.RequestEnvelop()
    req1 = req.requests.add()
    req1.type = 2
    if len(reqq) >= 1:
        req1.MergeFrom(reqq[0])

    req2 = req.requests.add()
    req2.type = 126
    if len(reqq) >= 2:
        req2.MergeFrom(reqq[1])

    req3 = req.requests.add()
    req3.type = 4
    if len(reqq) >= 3:
        req3.MergeFrom(reqq[2])

    req4 = req.requests.add()
    req4.type = 129
    if len(reqq) >= 4:
        req4.MergeFrom(reqq[3])

    req5 = req.requests.add()
    req5.type = 5
    if len(reqq) >= 5:
        req5.MergeFrom(reqq[4])

    return retrying_api_req(api, access_token, lat, long, req, useauth=useauth)


def login_ptc(username, password):
    print('[!] login for: {}'.format(username))
    head = {'User-Agent': 'Niantic App'}
    r = SESSION.get(LOGIN_URL, headers=head)
    if r is None:
        return render_template('nope.html', fullmap=fullmap)

    try:
        jdata = json.loads(r.content)
    except ValueError as e:
        debug("login_ptc: could not decode JSON from {}".format(r.content))
        return None

    # Maximum password length is 15 (sign in page enforces this limit, API does not)
    if len(password) > 15:
        print('[!] Trimming password to 15 characters')
        password = password[:15]

    data = {
        'lt': jdata['lt'],
        'execution': jdata['execution'],
        '_eventId': 'submit',
        'username': username,
        'password': password,
    }
    r1 = SESSION.post(LOGIN_URL, data=data, headers=head)

    ticket = None
    try:
        ticket = re.sub('.*ticket=', '', r1.history[0].headers['Location'])
    except Exception as e:
        if DEBUG:
            print(r1.json()['errors'][0])
        return None

    data1 = {
        'client_id': 'mobile-app_pokemon-go',
        'redirect_uri': 'https://www.nianticlabs.com/pokemongo/error',
        'client_secret': PTC_CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'code': ticket,
    }
    r2 = SESSION.post(LOGIN_OAUTH, data=data1)
    access_token = re.sub('&expires.*', '', r2.content)
    access_token = re.sub('.*access_token=', '', access_token)

    return access_token


def get_heartbeat(api_endpoint, access_token, response, lat, long):
    m4 = pokemon_pb2.RequestEnvelop.Requests()
    m = pokemon_pb2.RequestEnvelop.MessageSingleInt()
    m.f1 = int(time.time() * 1000)
    m4.message = m.SerializeToString()
    m5 = pokemon_pb2.RequestEnvelop.Requests()
    m = pokemon_pb2.RequestEnvelop.MessageSingleString()
    m.bytes = "05daf51635c82611d1aac95c0b051d3ec088a930"
    m5.message = m.SerializeToString()
    walk = sorted(getNeighbors(lat, long))
    m1 = pokemon_pb2.RequestEnvelop.Requests()
    m1.type = 106
    m = pokemon_pb2.RequestEnvelop.MessageQuad()
    m.f1 = ''.join(map(encode, walk))
    m.f2 = "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
    m.lat = f2i(lat)
    m.long = f2i(long)
    m1.message = m.SerializeToString()
    response = get_profile(
        access_token,
        api_endpoint,
        response.unknown7,
        f2i(lat), f2i(long),
        m1,
        pokemon_pb2.RequestEnvelop.Requests(),
        m4,
        pokemon_pb2.RequestEnvelop.Requests(),
        m5)
    if response is None:
        return
    payload = response.payload[0]
    heartbeat = pokemon_pb2.ResponseEnvelop.HeartbeatPayload()
    heartbeat.ParseFromString(payload)
    return heartbeat


def visit_stop(api_endpoint, access_token, response, stopid, ulat, ulong, lat, long):
    if haversine(ulong, ulat, long, lat) > 0.1:
        return

    print "visiting"
    time.sleep(20)

    m4 = pokemon_pb2.RequestEnvelop.Requests()
    m = pokemon_pb2.RequestEnvelop.MessageSingleInt()
    m.f1 = int(time.time() * 1000)
    m4.message = m.SerializeToString()
    m5 = pokemon_pb2.RequestEnvelop.Requests()
    m = pokemon_pb2.RequestEnvelop.MessageSingleString()
    m.bytes = "05daf51635c82611d1aac95c0b051d3ec088a930"
    m5.message = m.SerializeToString()
    walk = sorted(getNeighbors(lat, long))
    m1 = pokemon_pb2.RequestEnvelop.Requests()
    m1.type = 101
    m = pokemon_pb2.RequestEnvelop.MessageStop()
    m.fortid = stopid
    m.ulat = f2i(ulat)
    m.lat = f2i(lat)
    m.ulong = f2i(ulong)
    m.long = f2i(long)
    m1.message = m.SerializeToString()
    response = get_profile(
        access_token,
        api_endpoint,
        response.unknown7,
        f2i(lat), f2i(long),
        m1,
        pokemon_pb2.RequestEnvelop.Requests(),
        m4,
        pokemon_pb2.RequestEnvelop.Requests(),
        m5)
    print response
    if response is None:
        return
    payload = response.payload[0]
    heartbeat = pokemon_pb2.ResponseEnvelop.HeartbeatPayload()
    heartbeat.ParseFromString(payload)
    return heartbeat


def get_token(name, passw):
    return login_ptc(name, passw)

def main():
    debug("main")

    resetSession()

    full_path = os.path.realpath('__file__')
    path, filename = os.path.split(full_path)
    pokemonsJSON = json.load(open(path + '/pokemon.json'))

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", help="PTC Username", required=True)
    parser.add_argument("-p", "--password", help="PTC Password", required=True)
    parser.add_argument("-l", "--location", type=parse_unicode, help="Location", required=True)
    parser.add_argument("-st", "--step_limit", help="Steps", required=True)
    parser.add_argument("-i", "--ignore", help="Pokemon to ignore (comma separated)")
    parser.add_argument("-d", "--debug", help="Debug Mode", action='store_true')
    parser.add_argument("-c", "--china", help="Coord Transformer for China", action='store_true')
    parser.add_argument("-dp", "--display-pokestop", help="Display Pokestop", action='store_true', default=False)
    parser.add_argument("-dg", "--display-gym", help="Display Gym", action='store_true', default=False)
    parser.set_defaults(DEBUG=True)
    args = parser.parse_args()

    if args.debug:
        global DEBUG
        DEBUG = True
        print('[!] DEBUG mode on')

    loc = retrying_set_location(args.location)

    access_token = get_token(args.username, args.password)
    if access_token is None:
        print('[-] Wrong username/password')
        return
    print('[+] RPC Session Token: {} ...'.format(access_token[:25]))

    api_endpoint = get_api_endpoint(access_token, f2i(loc[0]), f2i(loc[1]))
    if api_endpoint is None:
        print('[-] RPC server offline')
        return
    print('[+] Received API endpoint: {}'.format(api_endpoint))

    profile_response = retrying_get_profile(access_token, api_endpoint, None, f2i(loc[0]), f2i(loc[1]))
    if profile_response is None or not profile_response.payload:
        print('[-] Ooops...')
        raise Exception("Could not get profile")

    print('[+] Login successful')

    payload = profile_response.payload[0]
    profile = pokemon_pb2.ResponseEnvelop.ProfilePayload()
    profile.ParseFromString(payload)
    print('[+] Username: {}'.format(profile.profile.username))

    creation_time = datetime.fromtimestamp(int(profile.profile.creation_time) / 1000)
    print('[+] You started playing Pokemon Go on: {}'.format(
        creation_time.strftime('%Y-%m-%d %H:%M:%S'),
    ))

    for curr in profile.profile.currency:
        print('[+] {}: {}'.format(curr.type, curr.amount))

    origin = LatLng.from_degrees(loc[0], loc[1])
    steps = 0
    steplimit = int(args.step_limit)

    ignore = []
    if args.ignore:
        ignore = [i.lower().strip() for i in args.ignore.split(',')]

    threads = {}
    while steps < steplimit**2*2:
        debug("looping: step {} of {}".format(steps, steplimit**2*2))

#        updateCell(steps, steplimit, loc, origin, profile_response, access_token, api_endpoint, args, pokemonsJSON)
        threads[steps] = threading.Thread(target = updateCell, args = (steps, steplimit, loc, origin, profile_response, access_token, api_endpoint, args, pokemonsJSON))
        threads[steps].start()

        if steps % 20 == 0:
            time.sleep(1)

        steps += 1

    steps = 0
    while steps < steplimit**2*2:
        threads[steps].join()
        steps += 1

    print "Done"

def updateCell(steps, steplimit, loc, origin, profile_response, access_token, api_endpoint, args, pokemonsJSON):
	try:
		_updateCell(steps, steplimit, loc, origin, profile_response, access_token, api_endpoint, args, pokemonsJSON)
        except Exception as err:
            print('Update error:', err)

def _updateCell(steps, steplimit, loc, origin, profile_response, access_token, api_endpoint, args, pokemonsJSON):
    x = (steps / (steplimit * 2)) - (steplimit / 2)
    y = (steps % (steplimit * 2)) - steplimit
    new_lat, new_long = [loc[0] + (x * 0.0025), loc[1] + (y * 0.0025)]

    parent = CellId.from_lat_lng(LatLng.from_degrees(new_lat, new_long)).parent(15)
    h = get_heartbeat(api_endpoint, access_token, profile_response, new_lat, new_long)
    hs = [h]
    seen = set([])
    for child in parent.children():
	time.sleep(2)
        latlng = LatLng.from_point(Cell(child).get_center())
        loc_ = [latlng.lat().degrees, latlng.lng().degrees]
        hs.append(get_heartbeat(api_endpoint, access_token, profile_response, loc_[0], loc_[1]))

    visible = []
    for hh in hs:
        try:
            for cell in hh.cells:
               for wild in cell.WildPokemon:
                   hash = wild.SpawnPointId + ':' + str(wild.pokemon.PokemonId)
                   if (hash not in seen):
                       visible.append(wild)
                       seen.add(hash)
               if cell.Fort:
                   for Fort in cell.Fort:
                       if Fort.Enabled == True:
                           if args.china:
                               Fort.Latitude, Fort.Longitude = transform_from_wgs_to_gcj(Location(Fort.Latitude, Fort.Longitude))
                           obj = {"updated": datetime.utcfromtimestamp(Fort.LastModifiedMs/1000), "lat": Fort.Latitude, "lon": Fort.Longitude}
                           if Fort.GymPoints:
                               obj["team"] = Fort.Team
                               obj["guard"] = Fort.GuardPokemonId
                               obj["guardcp"] = Fort.GuardPokemonLevel
                               obj["points"] = Fort.GymPoints
                           else:
                               pass
                               #visit_stop(api_endpoint, access_token, profile_response, Fort.FortId, new_lat, new_long, Fort.Latitude, Fort.Longitude)
                           if Fort.LureInfo.LureExpiresTimestampMs:
                               obj["lure"] = datetime.utcfromtimestamp(Fort.LureInfo.LureExpiresTimestampMs/1000)

                           mongo.waypoints.update({"_id": Fort.FortId}, {"$set": obj}, True)
        except AttributeError:
            break
    for poke in visible:
        pokename = pokemonsJSON[poke.pokemon.PokemonId - 1]['Name']
        if args.ignore:
            if pokename.lower() in ignore: continue
        other = LatLng.from_degrees(poke.Latitude, poke.Longitude)
        diff = other - origin
        # print(diff)
        difflat = diff.lat().degrees
        difflng = diff.lng().degrees

        disappear_timestamp = time.time() + poke.TimeTillHiddenMs/1000
        disappear_time_formatted = datetime.utcfromtimestamp(disappear_timestamp)

        if args.china:
            poke.Latitude, poke.Longitude = transform_from_wgs_to_gcj(Location(poke.Latitude, poke.Longitude))

        mongo.wild.update({"_id": poke.SpawnPointId + ":" + str(poke.pokemon.PokemonId)}, {"$setOnInsert": {"found": datetime.utcnow()}, "$set": {"dex": poke.pokemon.PokemonId, "lat": poke.Latitude, "lon": poke.Longitude, "gone": disappear_time_formatted}}, True)

while True:
	time.sleep(10)
	try:
		main()
        except Exception as err:
            print('Main error:', err)
