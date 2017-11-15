function initMap() {
    var detailsOfDboys= document.querySelector('#details');
    var gmarker = [];
    var location = [];
    var database = firebase.database().ref();
    database.on("value", function(datasnap) {
        datasnap.forEach(function(child) {
            child.forEach(function(subchild) {
                var data = subchild.val();
                console.log(data);
                var lat = data.lati;
                var lng = data.logi;
                var number = data.number;
                var loc = {
                    lat: lat,
                    lng: lng
                };
                console.log(loc);

                if (chcker(number, lat, lng)) {
                    console.log("updated");
                } else {
                    location.push(data);
                }

                function chcker(number, lat, lng) {
                    console.log("in checkr");
                    for (var i = 0; i < location.length; i++) {
                        if (location[i].number == number) {

                            console.log('chcker inside' + number);
                            console.log("before " + location[i].lati);
                            location[i].lati = lat;
                            console.log("after" + location[i].lati);
                            console.log("before " + location[i].logi);
                            location[i].logi = lng;
                            console.log("after " + location[i].logi);

                            return true;
                        }
                    }
                }

            });

        });

        for (var i = 0; i < location.length; i++) {
            console.log(location[i]);
            addmarker(location[i]);

        }
    });

    var myLatLng = {
        lat: 22.7196,
        lng: 75.8577
    };
    var marker;
    var cont;
    var bounds;

    var map = new google.maps.Map(document.getElementById('map'), {
        zoom: 11,
        center: myLatLng
    });




    function addmarker(finalsend) {

        var pos = {
            lat: finalsend.lati,
            lng: finalsend.logi
        };
        cont = finalsend.name;
        console.log("this is pos" + pos);
        var numb = finalsend.number;

        marker = new google.maps.Marker({
            position: pos,
            map: map,
            icon:'images/marker.png',
            number: numb
        });
        markercheck(numb);
        gmarker.push(marker);


        function markercheck(numb) {
            for (var i = 0; i < gmarker.length; i++) {
                    console.log("gmarker number"+ gmarker[i].number);
                    console.log("numb"+numb);

                if (gmarker[i].number == numb) {
                    gmarker[i].setMap(null);
                    console.log("gnaker set to null");

                }
            }


        }
        console.log("gmarkers" + gmarker);
        var infoWindow = new google.maps.InfoWindow({
            content: "name: "+cont+"<br>"+"mobile number :"+ numb,

            //}
        });
        //marker add listener

        marker.addListener('click', function() {
            //infoWindow.open(map, marker);
            var content ={name: finalsend.name, number: finalsend.number};
            setcontent(content);
      });

    }

}
function setcontent(content){
  var detailsOfDboys = document.querySelector('#details');
  detailsOfDboys.innerHTML ="<strong>Name Of The Delivery Boys : </strong>"+content.name+"<br>"+"<strong>Mobile Number: </strong>"
  +content.number+"<br>"+"<a class='btn-success btn btn-large'> Assign</a>";
}
