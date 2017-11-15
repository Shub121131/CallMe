// Load google charts
google.charts.load('current', {
	'packages' : [ 'corechart' ]
});
google.charts.setOnLoadCallback(dailyOrdersChart);
google.charts.setOnLoadCallback(weeklyOrderschart);
google.charts.setOnLoadCallback(monthlyOrderschart);
// Draw the chart and set the chart values
function dailyOrdersChart() {

	var totalOrders = $('#dailyTotalOrders').text();
	var successfullOrders = $('#dailySuccessfullOrders').text();
	var failedOrders = $('#dailyFailedOrders').text();

	var dataDaily = google.visualization.arrayToDataTable([
			[ 'calls', totalOrders ], [ 'Successfull', successfullOrders ],
			[ 'failed', failedOrders ] ]);

	// Optional; add a title and set the width and height of the chart
	var options = {
		'title' : 'Daily report',
		'width' : 500,
		'height' : 400
	};

	// Display the chart inside the <div> element with id="piechart"
	var chart = new google.visualization.PieChart(document
			.getElementById('dailyReport'));
	chart.draw(dataDaily, options);

}

function weeklyOrderschart() {
	var totalOrders = $('#weeklyTotalOrders').text();
	var successfullOrders = $('#weeklySuccessfullOrders').text();
	var failedOrders = $('#weeklyFailedOrders').text();

	var dataWeekly = google.visualization.arrayToDataTable([
			[ 'calls', totalOrders ], [ 'Successfull', successfullOrders ],
			[ 'failed', failedOrders ] ]);
	var options = {
		'title' : 'weekly report',
		'width' : 500,
		'height' : 400
	};
	// Display the chart inside the <div> element with id="piechart"

	var chart = new google.visualization.PieChart(document
			.getElementById('weeklyReport'));
	chart.draw(dataWeekly, options);

}

function monthlyOrderschart() {

	var totalOrders = $('#monthlyTotalOrders').text();
	var successfullOrders = $('#monthlySuccessfullOrders').text();
	var failedOrders = $('#monthlyFailedOrders').text();

	var dataMonthly = google.visualization.arrayToDataTable([
			[ 'calls', totalOrders ], [ 'Successfull', successfullOrders ],
			[ 'failed', failedOrders ] ]);

	// Optional; add a title and set the width and height of the chart
	var options = {
		'title' : 'Monthly report',
		'width' : 500,
		'height' : 400
	};

	// Display the chart inside the <div> element with id="piechart"
	var chart = new google.visualization.PieChart(document
			.getElementById('monthlyReport'));
	chart.draw(dataMonthly, options);

}
