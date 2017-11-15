var km;
var amount;
function dist() {
	var origin = $('#origin').val();
	var destination = $('#destination').val();
	var distance_text = calculateDistance(origin, destination);
}

function calculateDistance(origin, destination) {
	var service = new google.maps.DistanceMatrixService();
	service.getDistanceMatrix({
		origins : [ origin ],
		destinations : [ destination ],
		travelMode : google.maps.TravelMode.DRIVING,
		unitSystem : google.maps.UnitSystem.IMPERIAL,
		avoidHighways : false,
		avoidTolls : false
	}, callback);
}

function callback(response, status) {
	if (status != google.maps.DistanceMatrixStatus.OK) {
		$('#result').html(err);
	} else {
		var origin = response.originAddresses[0];
		var destination = response.destinationAddresses[0];
		if (response.rows[0].elements[0].status === "ZERO_RESULTS") {
			$('#result').html(
					"Better get on a plane. There are no roads between "
							+ origin + " and " + destination);
		} else {
			var distance = response.rows[0].elements[0].distance;
			var distance_value = distance.value;
			var distance_text = distance.text;
			var miles = distance_text.substring(0, distance_text.length - 3);
			km = miles * 1.60934;
			if (km <= 5) {
				console
						.log("Inside distancecal.js : callback() :- total pickup/delivery :- "
								+ addMoreButtonCounter);
				amount = 50;
				amount = amount + (addMoreButtonCounter - 1) * 50
				console.log("Total service charge :- " + amount);
			} else {
				console
						.log("Inside distancecal.js : callback() :- total pickup/delivery :- "
								+ addMoreButtonCounter);
				amount = km * 10;
				amount = amount + (addMoreButtonCounter - 1) * 50
				console.log("Total service charge :- " + amount);
			}
			$('#result').html(
					"It is " + km + " Kilometers from " + origin + " to "
							+ destination + " total amount =" + amount);
			$('#costing').html(
					"Total Distance :" + km + "K.M " + " Total cost(service charge):" + amount
							+ "rs<br>Total number of pickup/delivery points :"+addMoreButtonCounter);
			$('#yesno').removeClass("hide");
		}
	}
}

// maps

var directionsDisplay;
var directionsService = new google.maps.DirectionsService();
var map;

function initialize() {
	directionsDisplay = new google.maps.DirectionsRenderer();
	var stockport = new google.maps.LatLng(22.7196, 75.8577);
	var mapOptions = {
		zoom : 15,
		center : stockport
	}
	map = new google.maps.Map(document.getElementById('map-canvas'), mapOptions);
	directionsDisplay.setMap(map);
}

function calcRoute() {
	var start = document.getElementById('origin').value;
	var end = document.getElementById('destination').value;
	var request = {
		origin : start,
		destination : end,
		travelMode : google.maps.TravelMode.DRIVING
	};
	directionsService
			.route(
					request,
					function(response, status) {
						if (status == google.maps.DirectionsStatus.OK) {
							directionsDisplay.setDirections(response);
						} else {
							alert("Sorry, no driving route can be found between these locations");
						}
					});
}

google.maps.event.addDomListener(window, 'load', initialize);

