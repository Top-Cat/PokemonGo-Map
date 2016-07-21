<?php

require_once "vendor/autoload.php";

$pJson = json_decode(file_get_contents("pokemon.json"));

$m = new MongoDB\Client(
        file_get_contents("mongo.conf"),
        [
                "connectTimeoutMS" => 500,
                "readPreference" => "nearest",
                "replicaSet" => "TC_HA",
        ]
);

error_reporting(E_ALL);
ini_set('display_errors', 1);

$since = min(intval($_GET['since']), time());
$mtime = new MongoDB\BSON\UTCDateTime($since * 1000);
$pokemon = $m->pokemon->wild->find(["found" => ["\$gt" => $mtime]], ["projection" => ["lat" => 1, "lon" => 1, "gone" => 1, "dex" => 1]]);

$response = [];
foreach ($pokemon as $poke) {
	unset($poke['_id']);
	$poke['name'] = $pJson[$poke['dex'] - 1]->Name;
	$poke['gone'] = intval(intval($poke['gone']."") / 1000);
	$response[] = $poke;
}

$ntime = new MongoDB\BSON\UTCDateTime(($since - 30) * 1000);
$mpoints = $m->pokemon->waypoints->find(["updated" => ["\$gt" => $ntime]]);
$waypoints = [];
foreach ($mpoints as $point) {
	unset($point['updated']);
	$point['type'] = isset($point['points']) ? "gym" : "pokestop";
	if (isset($point['lure'])) {
		$point['lure'] = intval(intval($point['lure']."") / 1000);
	}
	$waypoints[] = $point;
}

header("Content-Type: application/json");
print json_encode(['time' => time(), 'r' => $response, 'w' => $waypoints]);
