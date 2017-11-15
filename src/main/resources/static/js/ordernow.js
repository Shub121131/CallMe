// this variable is used as counter when there is more than one pickup or delivery points are used
var addMoreButtonCounter = 1;

// these two variables are used to reset value of dropdown when operation is
// cancelled
var currentElementId = -1;
var oldStatus;
// these variables are used to temporary store orderNumber and status when
// current status is changed
var tempOrderNumberForStatusChange;
var tempStatusForStatusChange;

// this variable is used to persist year selected by user in order reports
var selectedYear = -1;
var selectedMonth = -1;

var suspiciousActivity = "Warning,Suspicious Activity Detected.";
$(document).ready(function() {

	$("#cancelorder").click(function() {
		$("#commentBox").toggle()
		if (!$("#commentBox").css('visibility') === 'hidden') {
			// alert("visible");
		}
	});
	$("#addMore").click(function() {
		console.log("AddMore:- ");
		console.log("counter :- " + addMoreButtonCounter);
		// here we are checking for number of
		// pickup/delivery points
		// if they are less than 5 then only we
		// increase counter because
		// we are providing total 5 counters(1
		// is by default + this 4=5)
		if (addMoreButtonCounter < 5) {
			addMoreButtonCounter++;
			console.log("counter :- " + addMoreButtonCounter);
			// here we are removing remove
			// button because we will display
			// only one remove button
			$("#removeButton123").remove();
			// here we are creating label &
			// input box for pickup
			// point,delivery point & itemname
			var label = $("<label>").attr({
				'id' : "originLabel" + addMoreButtonCounter
			}).text('Pick Up Address:' + addMoreButtonCounter);
			var input = $('<input type="text">').attr({
				id : 'origin' + addMoreButtonCounter,
				placeholder : "order pick up address" + addMoreButtonCounter
			});
			var label2 = $("<label>").attr({
				'id' : "destinationLabel" + addMoreButtonCounter
			}).text('Delivery Address:' + addMoreButtonCounter);
			var input2 = $('<input type="text">').attr({
				id : 'destination' + addMoreButtonCounter,
				placeholder : "order delivery address" + addMoreButtonCounter
			});
			var label3 = $("<label>").attr({
				'id' : "itemLabel" + addMoreButtonCounter
			}).text('Order :' + addMoreButtonCounter);
			var input3 = $('<input type="text">').attr({
				id : 'itemName' + addMoreButtonCounter,
				placeholder : "order " + addMoreButtonCounter + " name"
			});
			var button = $("<button>").attr({
				'type' : "button",
				'id' : 'removeButton123'
			}).text('Remove');

			// here we are adding all the three
			// label and input box & itemname to
			// UI
			input.appendTo(label);
			input2.appendTo(label2);
			input3.appendTo(label3);
			button.appendTo(label3);
			$('#locationDiv').append(label);
			$('#locationDiv').append(label2);
			$('#locationDiv').append(label3);
		}
	});

	// this function is called when the remove button is clicked
	$('#locationDiv').on('click', '#removeButton123', function() {
		console.log("RemoveButton :-");
		console.log("counter :- " + addMoreButtonCounter);
		// here we are checking for counter if it is
		// less than 6 i.e 5 so we remove
		// all the three label & input boxes & itemname
		// from UI
		if (addMoreButtonCounter < 6) {
			$("#originLabel" + addMoreButtonCounter).remove();
			$("#destinationLabel" + addMoreButtonCounter).remove();
			$("#itemLabel" + addMoreButtonCounter).remove();
			$("#origin" + addMoreButtonCounter).remove();
			$("#destination" + addMoreButtonCounter).remove();
			$("#itemName" + addMoreButtonCounter).remove();
			$(this).remove();
			// as we remove one entry of
			// pickup/delivery/itemname we also decrease
			// addMoreButtonCounter to -1
			addMoreButtonCounter--;
			// here we are appending remove button on UI
			// only if pickup/delivery/item name is
			// greater than 1
			if (addMoreButtonCounter > 1) {
				var button = $("<button>").attr({
					'type' : "button",
					'id' : 'removeButton123'
				}).text('Remove');
				$('#locationDiv').append(button);
			}
			console.log("counter :- " + addMoreButtonCounter);
		}
	});
	/*
	 * // This function is called when status filter is changed and // it will
	 * fetch data of corrosponding status from DB $("#byStatus") .change(
	 * function() { var status = $(this).val(); console.log("status " + status);
	 * 
	 * //This is used to check whether value of selected option(status) is zero
	 * if it will be zero then we display select correct status else we forward
	 * request
	 * 
	 * if (status.length == 0) { alert("Please select the correct status"); }
	 * else {
	 * 
	 * try { $("#trackOrderTable") .load( "/filter-orders-by-status?status=" +
	 * status, function() { // This modal // will be shown // if // any error or //
	 * suspicious // activity is // found $( '#SuspiciousActivityModal') .modal( {
	 * backdrop : 'static', keyboard : true, show : true }); }); } catch (err) {
	 * var r console.log(err); } // } }); // This function is used to filter
	 * track order by // time(today,last 7 days,this month,till date)
	 * $("#byTime").change( function() { var date = $(this).val();
	 * console.log("date " + date); $("#trackOrderTable").load(
	 * "/filter-orders-by-date?date=" + date, function() { // This modal will be
	 * shown if // any error or suspicious // activity is found
	 * $('#SuspiciousActivityModal') .modal({ backdrop : 'static', keyboard :
	 * true, show : true }); }); }); // This function is used to filter track
	 * order by // assignment(assigned or not assigned(deliveryBoys))
	 * $("#byAssignment").change( function() { var assignment = $(this).val();
	 * console.log("assignment " + assignment); $("#trackOrderTable").load(
	 * "/filter-orders-by-assignment?assignment=" + assignment, function() { //
	 * This modal will be shown if // any error or suspicious // activity is
	 * found $('#SuspiciousActivityModal') .modal({ backdrop : 'static',
	 * keyboard : true, show : true }); }); });
	 */

	$("#trackDeliverySearchButton").click(function() {
		console.log("Search Button Called...");
		var searchKey = $("#trackDeliverySearchKey").val();
		var trimmedSearchKey = searchKey.trim();
		if (trimmedSearchKey.length == 0) {
			alert("Enter search key to search something...");
		} else {
			console.log("searchKey " + searchKey);
			// here we set empty value in
			// filters
			$('#byStatus').val("By Status");
			$('#byTime').val("By Time");
			$('#byAssignment').val("By Assignment");
			$("#trackOrderTable").load("/track-delivery-search", {
				"searchKey" : searchKey
			}, function() {
				// alert("Search
				// Success...");
			});
		}
	});

});

window.onload = highlightHeader;
function highlightHeader() {
	var currentURL = window.location.href;
	console.log("Current URL :- " + currentURL);
	$(".nav-link").removeClass("active");
	if (window.location.href.indexOf("homepage") > -1) {
		$('#homepageLink').addClass("active");
	} else if (window.location.href.indexOf("summary") > -1) {
		$('#homepageLink').addClass("active");
	} else if (window.location.href.indexOf("addemploy") > -1) {
		$('#addEmployeeLink').addClass("active");
	} else if (window.location.href.indexOf("reports") > -1) {
		$('#orderReportsLink').addClass("active");
	} else if (window.location.href.indexOf("trackdelivery") > -1) {
		$('#trackOrdersLink').addClass("active");
	} else if (window.location.href.indexOf("submitreport") > -1) {
		$('#submittionReportsLink').addClass("active");
	} else {
		console.log("HOMEPAGE");
	}
}

// this function save edited product price to DB
function saveProductPrice(orderNumber) {
	var productPrice = $("#productPriceOf-" + orderNumber).val();
	console.log("inside saveProductPrice :product price :- " + productPrice);
	// Here we check whether product price is greater then zero
	// if it is greater than zero then only we will process otherwise we give
	// message "Product price should be greater than zero"
	if (productPrice > 0) {
		// here we are fetching filters value inorder to send them to controller
		// so that after completing request the user will be redirected to same
		// page
		var status = $('#byStatus').val();
		var date = $('#byTime').val();
		var assignment = $('#byAssignment').val();
		console.log("status :- " + status + " date :- " + date
				+ " assignment :- " + assignment);
		// check whether input box(which contains product price) is disabled or
		// not
		// if enabled then only we process request
		var isDisabled = $("#productPriceOf-" + orderNumber).prop('disabled');
		if (!isDisabled) {
			$("#trackOrderTable").load(
					"/save-product-price-of-order?status=" + status + "&date="
							+ date + "&assignment=" + assignment
							+ "&orderNumber=" + orderNumber + "&productPrice="
							+ productPrice,
					function(response, status, xhr) {
						console.log(response);
						// disabling product price input box after successfull
						// saving product price
						$("#productPriceOf-" + orderNumber).prop('disabled',
								true);
						$("#SuspiciousActivityModal").modal({
							backdrop : 'static',
							keyboard : false,
							show : true
						});
					});
		} else {
			alert("Warning, suspicious activity found.");
		}

	} else {
		alert("Product price should be greater than zero");
	}

}

// this function is used to enable product price box.
function editProductPrice(orderNumber) {
	// here we check whether box is enabled or disabled
	// if disabled then only we enable otherwise we won't perform any action
	var isDisabled = $("#productPriceOf-" + orderNumber).prop('disabled');
	if (isDisabled) {
		console.log("input box enabled OrderNumber : " + orderNumber);
		$("#productPriceOf-" + orderNumber).prop('disabled', false);
		$("#saveButton-" + orderNumber).prop('disabled', false);
	}
}

function getDetailsOfOrder(forDate) {
	var forDailyTotalOrderReport = 1;
	var forDailySuccessfullOrderReport = 2;
	var forDailyFailedOrderReport = 3;
	var forWeeklyTotalOrderReport = 4;
	var forWeeklySuccessfullOrderReport = 5;
	var forWeeklyFailedOrderReport = 6;
	console.log("Inside getDetailsOfOrder : ForDate :- " + forDate);

	if (forDate == forDailyTotalOrderReport
			|| forDate == forDailySuccessfullOrderReport
			|| forDate == forDailyFailedOrderReport
			|| forDate == forWeeklyTotalOrderReport
			|| forDate == forWeeklySuccessfullOrderReport
			|| forDate == forWeeklyFailedOrderReport) {
		$("#orderReportsModal").load("/get-order-reports?forDate=" + forDate,
				function() {
					$('#reportsModal').modal({
						backdrop : 'static',
						keyboard : true,
						show : true
					});
				});
	} else {
		alert(suspiciousActivity);
	}

}

function getMonthlyDetailsOfOrder(forDate) {
	var forMonthlyTotalOrderReport = 1;
	var forMonthlySuccessfullOrderReport = 2;
	var forMonthlyFailedOrderReport = 3;
	if (selectedYear == -1) {
		alert("Please select year from dropdown.");
	} else if (selectedYear < 2015) {
		alert(suspiciousActivity);
	} else if (selectedYear > 2030) {
		alert(suspiciousActivity);
	} else if (selectedMonth == -1) {
		alert(suspiciousActivity);
	} else if (selectedMonth > 0 && selectedMonth < 13) {
		if (forDate == forMonthlyTotalOrderReport
				|| forDate == forMonthlySuccessfullOrderReport
				|| forDate == forMonthlyFailedOrderReport) {
			console.log("Inside getMonthlyDetailsOfOrder() :- forDate :-"
					+ forDate + " Year :- " + selectedYear + " Month :- "
					+ selectedMonth);
			$("#orderReportsModal").load(
					"/get-monthly-order-reports?forDate=" + forDate
							+ "&selectedYear=" + selectedYear
							+ "&selectedMonth=" + selectedMonth, function() {

						$('#reportsModal').modal({
							backdrop : 'static',
							keyboard : true,
							show : true
						});
					});
		} else {
			alert(suspiciousActivity);
		}

	} else {
		alert(suspiciousActivity);
	}

}

function saveYear(year) {
	selectedYear = $(year).val();
	console.log("Save year : year :- " + selectedYear);
}

// This function is called when user select month from order reports section
function showMonthDetails(month) {
	selectedMonth = $(month).val();
	if (selectedYear == -1) {
		alert("Please select year from dropdown.");
	} else if (selectedYear < 2015) {
		alert("Warning,Suspicious Activity Detected.");
	} else if (selectedYear > 2030) {
		alert("Warning,Suspicious Activity Detected.");
	} else {
		console.log("Inside showMonthDetails(): Selected Month :- "
				+ selectedMonth + " Selected Year : " + selectedYear);
		if (selectedMonth > 0 && selectedMonth < 13) {
			$("#monthlyReportDetails").load(
					"/get-monthly-detail-of-order?selectedMonth="
							+ selectedMonth + "&selectedYear=" + selectedYear,
					function() {
						/*
						 * $("#monthlyReport").load( window.location.href + "
						 * #monthlyReport");
						 */
					});
		} else {
			alert("Warning,Suspicious Activity Detected.");
		}
	}

}

// this function is called when escape key is pressed it is used to set default
// value of drop down(current status dropdown)
$(document).keyup(
		function(e) {
			if (e.keyCode == 27) {
				console.log("Escape Key Pressed : OldStatus :- " + oldStatus
						+ " currentElementId :- " + currentElementId);
				var myexp = '#' + currentElementId + ' option[value="'
						+ oldStatus + '"]';
				console.log(myexp);
				$(myexp).prop('selected', true);
				$("#reportsModal").modal('hide');
			}
			if (e.keyCode === 13) { // checks whether the pressed key is
				// "Enter"
				var currentURL = window.location.href;
				console.log("URL :- " + currentURL);
				if (currentURL.search("homepage.html") != -1) {
					console.log("Homepage : entry key pressed.");
					savePhoneNumber();
				}
				if (currentURL.search("addemploy.html") != -1) {
					console.log("AddEmployee : entry key pressed.");
					addEmployee();
				}
			}
		});

/*
 * this function will be called when clicked on Submit Money Button(at the time
 * of collecting money from delivery boy) first it will check whether any
 * delivery boy is selected from the list or not if not selected the it return
 * Please select delivery boy from the dropdown else it will check whether any
 * comment will be provided or not if not it will return please provide comments
 * else if will process request
 */
function submitMoney() {
	var comments = $('textarea#submitMoneyComment').val().trim();
	var selectedDeliveryBoyId = $("#deliveryBoyList").val();
	var selectedDeliveryBoyName = $(
			"#deliveryBoyList option[value='" + selectedDeliveryBoyId + "']")
			.text();

	console.log("Submit Money :- Comments :- " + comments
			+ " Selected Delivery Boy Id :- " + selectedDeliveryBoyId);
	if (selectedDeliveryBoyId == null) {
		alert("Please select delivery boy from Delivery Boys Name List");
	} else if (comments.length == 0) {
		alert("Comment can't be empty.");
	} else {
		$("#deliveryBoysPaymentDetails")
				.load(
						"update-money-submitted-by-delivery-boy",
						{
							"deliveryBoyId" : selectedDeliveryBoyId,
							"comments" : comments
						},
						function() {
							$("#selectedDeliveryBoyName").text(
									selectedDeliveryBoyName);
							$("#totalCollection").load(
									window.location.href + " #totalCollection");
							$('#SuspiciousActivityModal').modal({
								backdrop : 'static',
								keyboard : true,
								show : true
							});
						});
	}
}

/*
 * this function is called when money_provided_in_morning is updated(changed)
 * using edit button and input box and clicked on submit button
 */
function SaveMoneyProvided() {
	// here we fetch money provided in morning using id of input box
	var moneyProvidedInMorning = $("#moneyProvidedInputBox").val();
	var oldMoneyProvided = $("#oldMoneyProvided").val();
	var selectedBoyId = $("#deliveryBoyList").val();
	var selectedDeliveryBoyName = $(
			"#deliveryBoyList option[value='" + selectedBoyId + "']").text();
	console.log("Inside SaveMoneyProvided : moneyProvidedInMorning :- "
			+ moneyProvidedInMorning + " Delivery Boy Id :- " + selectedBoyId
			+ " Old value of money provided :- " + oldMoneyProvided);
	if (selectedBoyId == null) {
		alert("Please select delivery boy from Delivery Boys Name List");
	} else if (oldMoneyProvided == moneyProvidedInMorning) {
		alert("Old value and new value of money provided can't be same.");
	} else if (moneyProvidedInMorning < 0) {
		alert("Money provided in morning should be greater than zero.");
	} else {
		// here we update money provided to delivery boy in db
		$("#deliveryBoysPaymentDetails")
				.load(
						"update-delivery-boy-money-provided?deliveryBoyId="
								+ selectedBoyId + "&moneyProvidedInMorning="
								+ moneyProvidedInMorning,
						function() {
							$("#selectedDeliveryBoyName").text(
									selectedDeliveryBoyName);
							$("#totalCollection").load(
									window.location.href + " #totalCollection");
							$('#SuspiciousActivityModal').modal({
								backdrop : 'static',
								keyboard : true,
								show : true
							});
						});
	}

}

function tripMoreDetails(orderNumber, selectedDeliveryBoyId) {
	console.log("TripMoreDetails :- OrderNumber : " + orderNumber
			+ " DeliveryBoyId : " + selectedDeliveryBoyId);
	$("#deliveryBoyTripMoreDetails").load(
			"get-more-detail-of-trip?orderNumber=" + orderNumber
					+ "&deliveryBoyId=" + selectedDeliveryBoyId, function() {

				$('#tripMoreDetailModal').modal({
					backdrop : 'static',
					keyboard : true,
					show : true
				});
				$('#SuspiciousActivityModal').modal({
					backdrop : 'static',
					keyboard : true,
					show : true
				});
			});

}

// this function is used to enable input box(money provided) when clicked on
// edit money provided button
function editMoneyProvided() {
	$("#moneyProvidedInputBox").prop('disabled', false);
}

// This function is called when delivery boy is selected from drop down from
// submission reports
function getDeliveryBoysDetailsFunc(id) {
	console.log("Inside getDeliveryBoysDetailsFunc()");
	// here we are fetching delivery boy id which is selected from drop down
	var selectedDeliveryBoyId = $(id).val();
	// here we are fetching delivery boy name using it's id and drop down id
	var selectedDeliveryBoyName = $(
			"#deliveryBoyList option[value='" + selectedDeliveryBoyId + "']")
			.text();
	console.log("DeliveryBoy Id :- " + selectedDeliveryBoyId + " Name :-"
			+ selectedDeliveryBoyName);
	// here we fetch selected delivery boy payment details
	$("#deliveryBoysPaymentDetails").load(
			"delivery-boy-payment-details?deliveryBoyId="
					+ selectedDeliveryBoyId,
			function() {
				// here we are showing selected delivery boy name in :Name of
				// delivery boy section
				$("#selectedDeliveryBoyName").text(selectedDeliveryBoyName);
				// here we fetch selected delivery boy trip details
				$("#deliveryBoysTripDetails")
						.load(
								"delivery-boy-trip-details?deliveryBoyId="
										+ selectedDeliveryBoyId,
								function() {
									$("#totalCollection").load(
											window.location.href
													+ " #totalCollection");

									$('#SuspiciousActivityModal').modal({
										backdrop : 'static',
										keyboard : true,
										show : true
									});
								});
				$('#SuspiciousActivityModal').modal({
					backdrop : 'static',
					keyboard : true,
					show : true
				});
			});

}

function filterTrackOrder() {
	// Here we set empty value for search key
	$("#trackDeliverySearchKey").val("");
	var status = $('#byStatus').val();
	var date = $('#byTime').val();
	var assignment = $('#byAssignment').val();
	console.log("status :- " + status + " date :- " + date + " assignment :- "
			+ assignment);

	$('#trackOrderTable').load(
			"/filter-track-order?status=" + status + "&date=" + date
					+ "&assignment=" + assignment, function() {
				// This modal will be shown if
				// any error or suspicious
				// activity is found
				$('#SuspiciousActivityModal').modal({
					backdrop : 'static',
					keyboard : true,
					show : true
				});
			});

}

function savePendingOrDeliveredOrderStatus() {
	var status = $('#byStatus').val();
	var date = $('#byTime').val();
	var assignment = $('#byAssignment').val();
	console.log("status :- " + status + " date :- " + date + " assignment :- "
			+ assignment);

	$("#trackOrderTable").load(
			"/save-pending-or-delivered-status-of-order?status=" + status
					+ "&date=" + date + "&assignment=" + assignment
					+ "&orderNumber=" + tempOrderNumberForStatusChange
					+ "&newStatus=" + tempStatusForStatusChange, function() {
				$('#SuspiciousActivityModal').modal({
					backdrop : 'static',
					keyboard : true,
					show : true
				});
			});
}

function savefailedOrderStatus() {
	var failedComments = $("#failedStatusComments").val();
	var status = $('#byStatus').val();
	var date = $('#byTime').val();
	var assignment = $('#byAssignment').val();
	console.log("status :- " + status + " date :- " + date + " assignment :- "
			+ assignment);
	console.log("Failed Status Comments :- " + failedComments);
	if (!failedComments && failedComments.trim().length == 0) {
		alert("Failed status comments can't be empty.");
	} else {
		$("#trackOrderTable").load("/save-failed-status-comments-of-order", {
			"status" : status,
			"date" : date,
			"assignment" : assignment,
			"orderNumber" : tempOrderNumberForStatusChange,
			"newStatus" : tempStatusForStatusChange,
			"failedComments" : failedComments
		}, function() {
			$("#failedStatusComments").val("");
			$('#SuspiciousActivityModal').modal({
				backdrop : 'static',
				keyboard : true,
				show : true
			});
		});
	}
}

// This function is called when status confirmation modal is closed
function setDefaultStatus() {
	console.log("Set Default Status : OldStatus :- " + oldStatus
			+ " currentElementId :- " + currentElementId);
	var myexp = '#' + currentElementId + ' option[value="' + oldStatus + '"]';
	console.log(myexp);
	$(myexp).prop('selected', true);
}

// This function is called when current status is changed from current status
// dropdown
function currentOrderStatusFunc(orderNumber, currentStatus, previousStatus) {
	var status = $(currentStatus).val();
	currentElementId = $(currentStatus).attr('id');
	oldStatus = previousStatus;
	console.log("Pending Status OrderNumber :- " + orderNumber + "  Status :- "
			+ status + " currentElementId :- " + currentElementId
			+ " Previous Status :- " + oldStatus);
	// Here we check status value for null & length
	// if current status value is null or empty the a suspicious activity alert
	// is shown

	if (status && status.trim().length > 0) {
		if (status == "Failed") {
			// if status is failed the we show modal asking for failed
			// comments(reason why order is failed)
			tempOrderNumberForStatusChange = orderNumber;
			tempStatusForStatusChange = status;

			$("#failedStatusConfirmModal").modal({
				backdrop : 'static',
				keyboard : true,
				show : true
			});

		} else if (status == "Pending") {

			tempOrderNumberForStatusChange = orderNumber;
			tempStatusForStatusChange = status;
			$("#pendingOrDeliveredConfirmModal").modal({
				backdrop : 'static',
				keyboard : true,
				show : true
			});

		} else if (status == "Delivered") {
			var deliveryBoyNotAssigned = 0;
			var deliveryBoyStatus = $("#deliveryBoy" + orderNumber).val();
			if (deliveryBoyStatus == deliveryBoyNotAssigned) {
				alert("Delivery boy not assigned,assign delivery boy to change order status.");
				setDefaultStatus();
			} else {
				tempOrderNumberForStatusChange = orderNumber;
				tempStatusForStatusChange = status;
				$("#pendingOrDeliveredConfirmModal").modal({
					backdrop : 'static',
					keyboard : true,
					show : true
				});
			}
		}
	} else {
		alert("Suspicious Activity");
	}

}

function failedOrderStatus(orderNumber) {
	console.log("Order Number :- " + orderNumber);
	$("#failedOrderDetailsModal").load(
			"/comments-of-failed-order?orderNumber=" + orderNumber,
			function(response, status, xhr) {
				if (status == "success") {
					$("#failedOrderModal").modal({
						backdrop : 'static',
						keyboard : true,
						show : true
					});
				}
			});
}

function assignDeliveryBoyFunc(orderNumber, deliveryBoyId) {
	var status = $('#byStatus').val();
	var date = $('#byTime').val();
	var assignment = $('#byAssignment').val();
	console.log("status :- " + status + " date :- " + date + " assignment :- "
			+ assignment);
	var deliveryBoyId = $(deliveryBoyId).val();
	console.log("assignDeliveryBoyFunc() Order Number :- " + orderNumber
			+ " Delivery Body Id :- " + deliveryBoyId);
	$("#trackOrderTable").load("/assign-order-to-delivery-boy", {
		"status" : status,
		"date" : date,
		"assignment" : assignment,
		"orderNumber" : orderNumber,
		"deliveryBoyId" : deliveryBoyId
	}, function(response, status, xhr) {
		$("#suspiciousActivity").modal({
			backdrop : 'static',
			keyboard : false,
			show : true
		});
	});

}

/*
 * function deliveryBoyAssignment(orderNumber) { var deliveryBoyId =
 * $("#assignDeliveryBoy").val(); alert("delivery boy id :- " +
 * $("#assignDeliveryBoy").val() + " OrderNumber :- " + orderNumber); $.ajax({
 * url : "/assign-order-to-delivery-boy", method : "POST", data : {
 * "deliveryBoyId" : deliveryBoyId, "orderNumber" : orderNumber }, success :
 * function(data) { if (data == "success") { alert("Delivery Boy successfully
 * assigned."); } else if (data == "fail") { alert("Delivery Boy assignment
 * failed."); } }, error : function() { alert("some error occured, try again") }
 * }); }
 */

function moreDetails(orderNumber) {
	// this function is used to fetch more details of corrosponding order(for
	// multiple orders)
	console.log("More details for order number :- " + orderNumber);
	$("#moreDetailModal").load(
			"/more-detail-of-order?orderNumber=" + orderNumber, function() {
				$("#orderDetailsModal").modal({
					backdrop : 'static',
					keyboard : true,
					show : true
				});
			});
}

// this function is called when placeorder button is clicked
function placeOrder() {
	console.log("placeorder");
	var newCustomer = $("#newCustomer").val();
	console.log("New Customer :- " + newCustomer);
	// here we are checking for new customer
	if (newCustomer == "TRUE") {

		// if customer is new the we will store it's details
		var comments = $("#commentContent").val();
		var customerFirstName = $("#customerFirstName").val();
		var customerLastName = $("#customerLastName").val();
		var customerAddress = $("#customerAddress").val();
		// here we are using array to store item name,pickup & delivery
		// because we are dealing with multiple pickup's & delivery's point
		var itemName = [];
		itemName[0] = $("#itemName").val() + "&#@";
		var orderPickedFrom = [];
		orderPickedFrom[0] = $("#origin").val() + "&#@";
		var orderDeliveredAt = [];
		orderDeliveredAt[0] = $("#destination").val() + "&#@";
		console.log("itemName[0] " + itemName[0] + " orderPickedFrom [0] "
				+ orderPickedFrom[0] + " orderDeliveredAt [0] "
				+ orderDeliveredAt[0]);

		var orderLength = addMoreButtonCounter;

		console.log("orderLength" + orderLength);
		// this for loop is used for multiple pickup/delivery points
		// here we are storing multiple pickup's & delivery's point by
		// seperating them by "&#@" pattern
		// we will use thing pattern to fetch these points at server side while
		// storing in DB
		if (orderLength > 1) {
			for (var i = 1; i < orderLength; i++) {
				// here we start for loop from 1 because by default we have one
				// pickup/delivery
				// here we are fetching value of itemname,orgin,destination by
				// using their id
				// starting from 2 to 5
				itemName[i] = $("#itemName" + (i + 1)).val() + "&#@";
				orderPickedFrom[i] = $("#origin" + (i + 1)).val() + "&#@";
				orderDeliveredAt[i] = $("#destination" + (i + 1)).val() + "&#@";
				console.log("Value of i " + i);
				console.log("itemName[" + i + "] " + itemName[i]
						+ " orderPickedFrom [" + i + "] " + orderPickedFrom[i]
						+ " orderDeliveredAt [" + i + "] "
						+ orderDeliveredAt[i]);
			}
		}
		var totalDistance = parseInt(km);
		var serviceCharge = parseFloat(amount);
		// here we are converting all the itemnames/delivery,pickup points to
		// String
		// because we need to send it using ajax request
		var itemNameString = JSON.stringify(itemName);
		var orderPickedFromString = JSON.stringify(orderPickedFrom);
		var orderDeliveredAtString = JSON.stringify(orderDeliveredAt);
		console.log(orderPickedFrom.length + " " + orderDeliveredAt.length
				+ " " + totalDistance + " " + serviceCharge);
		console.log("comments :- " + comments);
		if (customerFirstName.length == 0) {
			alert("First Name can't be empty");
		} else if (itemName.length == 0) {
			alert("Item Name can't be empty");
		} else if (orderPickedFrom.length == 0) {
			alert("Picking address can't be empty");
		} else if (orderDeliveredAt.length == 0) {
			alert("Delivery address can't be empty");
		} else {
			$.ajax({
				url : '/save-new-customer-and-order',
				type : 'POST',
				data : {
					"comments" : comments,
					"customerFirstName" : customerFirstName,
					"customerLastName" : customerLastName,
					"customerAddress" : customerAddress,
					"itemName" : itemNameString,
					"orderPickedFrom" : orderPickedFromString,
					"orderDeliveredAt" : orderDeliveredAtString,
					"totalDistance" : totalDistance,
					"serviceCharge" : serviceCharge,
					"totalNumberOfOrders" : orderLength
				},
				success : function(result) {
					console.log(result);
					if (result == "emptyFirstName") {
						alert("FirstName can't be empty");
					} else if (result == "emptyItem") {
						alert("Item can't be empty");
					} else if (result == "emptyPickupLocation") {
						alert("Pickup location can't be empty");
					} else if (result == "emptyDeliveryLocation") {
						alert("Delivery location can't be empty");
					} else if (result == "incorrectDistance") {
						alert("Distance can't be 0");
					} else if (result == "incorrectServiceCharge") {
						alert("Service Charge can't be 0");
					} else if (result == "success") {
						console.log("success");
						location.href = "homepage.html";
						alert("Operation successfull.");
					} else if (result == "fail") {
						console.log("fail");
						location.href = "summary.html"
						alert("Operation failed, try again.");
					}
				},
				error : function(xhr, textStatus, error) {
					console.log("Error occured " + error);
					location.href = "summary.html";
				}
			});
		}

	} else if (newCustomer == "FALSE") {

		// if customer is existing then we will not store it's details
		var comments = $("#commentContent").val();
		var itemName = [];
		itemName[0] = $("#itemName").val() + "&#@";
		var orderPickedFrom = [];
		orderPickedFrom[0] = $("#origin").val() + "&#@";
		var orderDeliveredAt = [];
		orderDeliveredAt[0] = $("#destination").val() + "&#@";
		console.log("itemName[0] " + itemName[0] + " orderPickedFrom [0] "
				+ orderPickedFrom[0] + " orderDeliveredAt [0] "
				+ orderDeliveredAt[0]);
		var orderLength = addMoreButtonCounter;
		console.log("orderLength" + orderLength);
		if (orderLength > 1) {
			for (var i = 1; i < orderLength; i++) {
				itemName[i] = $("#itemName" + (i + 1)).val() + "&#@";
				orderPickedFrom[i] = $("#origin" + (i + 1)).val() + "&#@";
				orderDeliveredAt[i] = $("#destination" + (i + 1)).val() + "&#@";
				console.log("Value of i " + i);
				console.log("itemName[" + i + "] " + itemName[i]
						+ " orderPickedFrom [" + i + "] " + orderPickedFrom[i]
						+ " orderDeliveredAt [" + i + "] "
						+ orderDeliveredAt[i]);
			}
		}
		var totalDistance = parseInt(km);
		var serviceCharge = parseFloat(amount);
		var itemNameString = JSON.stringify(itemName);
		var orderPickedFromString = JSON.stringify(orderPickedFrom);
		var orderDeliveredAtString = JSON.stringify(orderDeliveredAt);
		console.log(itemName.length + " " + orderPickedFrom.length + "  : "
				+ orderDeliveredAt.length + " " + totalDistance + " "
				+ serviceCharge);
		console.log("comments :- " + comments);
		if (itemName.length == 0) {
			alert("Item Name can't be empty");
		} else if (orderPickedFrom.length == 0) {
			alert("Picking address can't be empty");
		} else if (orderDeliveredAt.length == 0) {
			alert("Delivery address can't be empty");
		} else {
			$.ajax({
				url : '/saveNewOrderForExistingCustomer',
				type : 'POST',
				data : {
					"comments" : comments,
					"itemName" : itemNameString,
					"orderPickedFrom" : orderPickedFromString,
					"orderDeliveredAt" : orderDeliveredAtString,
					"totalDistance" : totalDistance,
					"serviceCharge" : serviceCharge,
					"totalNumberOfOrders" : orderLength
				},
				success : function(result) {
					console.log(result);
					if (result == "emptyItem") {
						alert("Item can't be empty");
					} else if (result == "emptyPickupLocation") {
						alert("Pickup location can't be empty");
					} else if (result == "emptyDeliveryLocation") {
						alert("Delivery location can't be empty");
					} else if (result == "incorrectDistance") {
						alert("Distance can't be 0");
					} else if (result == "incorrectServiceCharge") {
						alert("Service Charge can't be 0");
					} else if (result == "success") {
						console.log("success");
						location.href = "homepage.html";
						alert("Operation successfull.");
					} else if (result == "fail") {
						console.log("fail");
						location.href = "summary.html"
						alert("Operation failed, try again.");
					}
				},
				error : function(xhr, textStatus, error) {
					console.log("Error occured " + error);
					location.href = "summary.html"
				}
			});
		}
	}
}
function savePhoneNumber() {
	var clientPhoneNumber = $("#clientphone").val();
	console.log("client phonenumber " + clientPhoneNumber);
	var phoneNumberLength = clientPhoneNumber.length;
	if (phoneNumberLength < 10 || phoneNumberLength > 10) {
		alert("Phonenumber should contain 10 digits");
	} else {
		// alert("Correct Phone number");
		$.ajax({
			url : '/save-contact-number',
			type : 'POST',
			data : {
				'contactNumber' : clientPhoneNumber
			},
			success : function(result) {
				if (result == "incorrectPhoneNumber") {
					alert("Phonenumber should contain 10 digits");
					location.href = "homepage.html"
				} else if (result == "success") {
					location.href = "summary.html";
				} else if (result == "error") {
					alert("Some error occured, please try again");
					location.href = "homepage.html";
				}
			},
			error : function() {
				alert("Some error occured, please try again");
				location.href = "homepage.html"
			}
		});
	}
}

// this function is used to add employee
function addEmployee() {
	console.log("addEmployee");
	var username = $("#username").val();
	var firstname = $("#firstname").val();
	var lastname = $("#lastname").val();
	var password = $("#password").val();
	var email = $("#email").val();
	var confirmPassword = $("#confirmPassword").val();
	var employeeType = $("#employeeType").val();
	var mobileNumber = $("#contactNumber").val();
	console.log("FirstName " + firstname + " LastName " + lastname
			+ " UserName " + username + " Password " + password + " Email "
			+ email + " ConfirmPassword " + confirmPassword + " MobileNumber "
			+ mobileNumber + " Employee type :- " + employeeType);

	if (username.length == 0) {
		alert("User Name can't be empty");
	} else if (firstname.length == 0) {
		alert("First Name can't be empty");
	} else if (lastname.length == 0) {
		alert("Last Name can't be empty");
	} else if (mobileNumber.length == 0 || mobileNumber.length < 0
			|| mobileNumber.length > 10) {
		alert("Please enter valid mobile number");
	} else if (password.length == 0) {
		alert("Password  can't be empty");
	} else if (confirmPassword.length == 0) {
		alert("Confirm password can't be empty");
	} else if (password != confirmPassword) {
		alert("Passwords don't match, Try again");
	} else {
		$.ajax({
			url : "/addEmployee",
			method : "POST",
			data : {
				"userName" : username,
				"firstName" : firstname,
				"lastName" : lastname,
				"password" : password,
				"confirmPassword" : confirmPassword,
				"email" : email,
				"employeeType" : employeeType,
				"contactNumber" : mobileNumber
			},
			success : function(result) {

				console.log("Result :- " + result);
				if (result == "emptyUsername") {
					alert("Username can't be empty");
				} else if (result == "invalidContactNumber") {
					alert("Please enter a phone number");
				} else if (result == "userNameNotAvailable") {
					alert("Username exist, try another");
				} else if (result == "emptyFirstname") {
					alert("First Name can't be empty");
				} else if (result == "emptyLastName") {
					alert("Last Name can't be empty");
				} else if (result == "emptyPassword") {
					alert("Password can't be empty");
				} else if (result == "emptyConfirmPassword") {
					alert("Confirm Password  can't be empty");
				} else if (result == "passwordsDontMatch") {
					alert("Passwords don't match, try again");
				} else if (result == "fail") {
					alert("Some error occured, please try again");
				} else if (result == "phoneNumberNotAvailable") {
					alert("Phone number exist, try another.");
				} else if (result == "success") {
					alert("Employee added successfully...");
					location.href = "addemploy.html";
				}
			},
			error : function(xhr, textStatus, error) {
				console.log("Error occured " + error);
				location.href = "addemploy.html";
			}
		});
	}
}
