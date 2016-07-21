			var pStopImg = {
				url: "static/forts/changePstop.png",
				scaledSize: new google.maps.Size(20, 20),
				origin: new google.maps.Point(0, 0),
				anchor: new google.maps.Point(10, 10)
			};

			var pokemon = [];
			var waypoints = [];
			function getPokemons(since, map) {
				$.getJSON('api.php', {since: since}, function(data) {
					next = data.time;

					newArr = [];
					for (x in pokemon) {
						if (pokemon[x].gone < next) {
							pokemon[x].marker.setMap(null);
						} else {
							newArr.push(pokemon[x]);
						}
					}
					pokemon = newArr;

					for (x in waypoints) {
						if (typeof waypoints[x].lure !== "undefined" && waypoints[x].lure < next) {
							waypoints[x].marker.setIcon(pStopImg);
						}
					}

					for (x in data.r) {
						poke = data.r[x];

						var date = new Date(poke.gone*1000);
						var dateStr = ('0' + date.getHours()).substr(-2) + ':' + ('0' + date.getMinutes()).substr(-2) + ':' + ('0' + date.getSeconds()).substr(-2);

						var icon = {
							url: "static/icons/" + poke.dex + ".png",
							scaledSize: new google.maps.Size(40, 30),
							origin: new google.maps.Point(0, 0),
							anchor: new google.maps.Point(20, 15)
						};

						var marker_0 = new google.maps.Marker({
							position: new google.maps.LatLng(poke.lat, poke.lon),
							map: map,
							icon: icon
						});

						google.maps.event.addListener(
							marker_0,
							'click',
							getInfoCallback(map, "<div style='position:float; top:0;left:0;'><small><a href='http://www.pokemon.com/us/pokedex/" + poke.dex + "' target='_blank' title='View in Pokedex'>#" + poke.dex + "</a></small> - <b>" + poke.name + "</b></div><center>disappears at " + dateStr + "</center>")
						);

						poke.marker = marker_0;
						pokemon.push(poke);
					}

					for (x in data.w) {
						point = data.w[x];

						var img;
						var size = 20;
						var mid = 10;
						if (point.type == "gym") {
							size = Math.floor((Math.log(point.points) / Math.log(1.1)) - 70);
							mid = 100;
							img = "static/forts/" + point.team + ".png";
						} else if (point.lure > next) {
							img = "static/forts/PstopLured.png";
						} else {
							img = "static/forts/changePstop.png";
						}
						var icon = {
							url: img,
							scaledSize: new google.maps.Size(size, size),
							origin: new google.maps.Point(0, 0),
							anchor: new google.maps.Point(size/2, size/2)
						};

						var marker;
						if (typeof waypoints[point._id] === "undefined") {
							marker = new google.maps.Marker({
								position: new google.maps.LatLng(point.lat, point.lon),
								map: map,
								icon: icon
							});
						} else {
							//Update existing
							marker = waypoints[point._id].marker;
							marker.setIcon(icon);
						}

						point.marker = marker;
						waypoints[point._id] = point;
					}

					setTimeout(function() {
						getPokemons(next, map);
					}, 5000);
				});
			}

			function initialize_map() {
				var map = new google.maps.Map(
					document.getElementById('fullmap'), {
						center: new google.maps.LatLng(53.8017278, -1.5619364),
						zoom: 15,
						mapTypeId: google.maps.MapTypeId.ROADMAP,
						zoomControl: true,
						mapTypeControl: true,
						scaleControl: true,
						streetViewControl: true,
						rotateControl: true,
						fullscreenControl: true
					}
				);

				getPokemons(0, map);
			}

			function getInfoCallback(map, content) {
				var infowindow = new google.maps.InfoWindow({content: content});
				return function() {
					infowindow.setContent(content);
					infowindow.open(map, this);
				};
			}

			google.maps.event.addDomListener(window, 'load', initialize_map);
