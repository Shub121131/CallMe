//refrence to the database

var database = firebase.database().ref();
var Dnum=[];
var postlati=[];
var check=[];
var ocations =[];
database.on("value",function(datasnap){
	datasnap.forEach(function(child){
		console.log(child.val());
		child.forEach(function(subchild){
			var subchild = subchild.val();
			var number = subchild.number;
			var lat = subchild.lati;
			var lng = subchild.logi;
			var name = subchild.name;
			 var toset = {number:number,lat:lat,lng:lng,name:name};

		if(Dnum!=null){

			
		if(checkfornumber(number)){
			console.log("numebr already exists");
			initMap(toset);
		}
		else{
			console.log("number pushed")
			Dnum.push(toset);
			initMap(toset)
			console.log("new number added"+number);
		}
			}else
			Dnum.push(toset);
			initMap(toset)


		console.log("Dnum"+ Dnum);
		console.log("length"+ Dnum.length);		

		function checkfornumber(number){
			console.log("inside checkfornumber")
			for(var i =0;i<Dnum.length;i++){
			 	if(Dnum[i].number ==number){
			 		
			 		return true;
			 		
			 	}

			 }
		}	 

		});



		});

});



function initMap(finalsend) {
        var myLatLng = {lat: 22.7196, lng: 75.8577};
        var marker;
        var map = new google.maps.Map(document.getElementById('map'), {
          zoom: 15,
          center: myLatLng 
         });
        console.log(finalsend);
        var number =finalsend.number;
        var name = finalsend.name;
        var lat =finalsend.lat;
        var lng = finalsend.lng;
        var loc=[];
        var checker = checkinloc(number);
        if(checker!=null){
        	loc[checker].lat=lat;
        	loc[checker].lng=lng;
        }else{
        loc.push({lat:lat,lng:lng,number:number});
		}
        
        for(var i =0;i<loc.length;i++){
        	addmarker(loc[i]);
       		console.log(i+loc[i].number);
        }
       
        //checkinloc()
        function checkinloc(number){
        	for(var i =0;i<loc.length;i++){
        		if(loc[i].number==number){
        			return i;
	        	}

        	}
        	        }

       function addmarker(finalsend){
       	console.log("in add marker");
       	var pos ={lat:finalsend.lat,lng:finalsend.lng};
       	var cont = finalsend.name;
       	console.log("this is pos"+pos);
       	 marker = new google.maps.Marker({
			position: pos,
			map:map
			
		});
       }
        var infoWindow = new google.maps.InfoWindow({
			content:'<h1>'+finalsend.numberq.num+'</h1>'
		});
		//marker add listener

		marker.addListener('click',function(){
			infoWindow.open(map,marker);

		});
      }
