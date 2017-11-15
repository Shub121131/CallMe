package com.ordernao.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.ordernao.bean.DeliveryBoyPaymentBean;
import com.ordernao.bean.EmployeeBean;
import com.ordernao.bean.OrderBean;
import com.ordernao.service.OrderService;
import com.ordernao.utility.OrderNaoConstants;

/**
 * @author shubham sharma
 *
 */
@Controller
public class OrderController {
	static final Logger logger = LogManager.getLogger(OrderController.class.getName());
	@Autowired
	OrderService service;

	@RequestMapping(value = OrderNaoConstants.PATH_MORE_ORDER_DETAILS_HTML_PAGE)
	public String moreDetails(HttpServletRequest request, HttpServletResponse response) {
		return OrderNaoConstants.PATH_MORE_ORDER_DETAILS_PAGE;
	}

	@RequestMapping(value = OrderNaoConstants.PATH_SUMMARY_HTML_PAGE)
	public String showHome(HttpServletRequest request, HttpServletResponse response) {
		return OrderNaoConstants.PATH_SUMMARY_PAGE;
	}

	@RequestMapping(value = OrderNaoConstants.PATH_SAVE_CONTACT_NUMBER, method = RequestMethod.POST)
	@ResponseBody
	public String saveContactNumber(@RequestParam(OrderNaoConstants.REQUEST_PARAM_CONTACT_NUMBER) String contactNumber,
			HttpServletRequest request, HttpServletResponse response, HttpSession session) {
		logger.info("Entry at SaveContactNumberMethod(Controller)");
		logger.debug("Contact Number :- " + contactNumber);
		if (contactNumber.isEmpty() || contactNumber.length() < OrderNaoConstants.MAX_MOBILE_NUMBER_LENGTH
				|| contactNumber.length() > OrderNaoConstants.MAX_MOBILE_NUMBER_LENGTH) {
			return OrderNaoConstants.RETURN_STATUS_INCORRECT_MOBILE_NUMBER;
		} else {
			session.invalidate();
			session = request.getSession();
			session.setAttribute(OrderNaoConstants.SESSION_ATTRIBUTE_CONTACT_NUMBER, contactNumber);
			OrderBean orderBean = service.checkExistingCustomer(contactNumber);
			logger.info("OrderBean :- " + orderBean.getCustomerFirstName());
			/* if (firstName != null) { */
			session.setAttribute(OrderNaoConstants.SESSION_ATTRIBUTE_ORDERBEAN, orderBean);
			boolean newCustomer = orderBean.isNewCustomer();
			if (newCustomer) {
				session.setAttribute(OrderNaoConstants.SESSION_ATTRIBUTE_NEW_CUSTOMER, OrderNaoConstants.STRING_TRUE);
			} else {
				session.setAttribute(OrderNaoConstants.SESSION_ATTRIBUTE_NEW_CUSTOMER, OrderNaoConstants.STRING_FALSE);
			}
			return OrderNaoConstants.RETURN_STATUS_SUCCESS;
			/*
			 * } else { return Constants.RETURN_STATUS_ERROR; }
			 */

		}

	}

	@RequestMapping(OrderNaoConstants.PATH_SAVE_NEW_CUSTOMER)
	@ResponseBody
	public String saveNewCustomer(@ModelAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ORDERBEAN) OrderBean orderBean,
			HttpSession session) {
		logger.info("Entry at saveNewCustomer(Controller) ");
		logger.info("Order Length :- " + orderBean.getTotalNumberOfOrders());
		String contactNumber = (String) session.getAttribute(OrderNaoConstants.SESSION_ATTRIBUTE_CONTACT_NUMBER);
		String customerFirstName = orderBean.getCustomerFirstName();
		String itemName = (String) orderBean.getItemName();
		String orderPickedFrom = (String) orderBean.getOrderPickedFrom();
		String orderDeliveredAt = (String) orderBean.getOrderDeliveredAt();
		int totalDistance = orderBean.getTotalDistance();
		double serviceCharge = orderBean.getServiceCharge();
		if (customerFirstName == null || customerFirstName.isEmpty()) {
			return OrderNaoConstants.RETURN_STATUS_EMPTY_FIRSTNAME;
		} else if (itemName == null || itemName.isEmpty()) {
			return OrderNaoConstants.RETURN_STATUS_EMPTY_ITEM;
		} else if (orderPickedFrom == null || orderPickedFrom.isEmpty()) {
			return OrderNaoConstants.RETURN_STATUS_EMPTY_PICKUP_LOCATION;
		} else if (orderDeliveredAt == null || orderDeliveredAt.isEmpty()) {
			return OrderNaoConstants.RETURN_STATUS_EMPTY_DELIVERY_LOCATION;
		} else if (totalDistance < 0) {
			return OrderNaoConstants.RETURN_STATUS_INCORRECT_DISTANCE;
		} else if (serviceCharge < 0) {
			return OrderNaoConstants.RETURN_STATUS_INCORRECT_SERVICE_CHARGE;
		}
		orderBean.setCustomerPhone(contactNumber);

		try {
			boolean status = service.saveNewCustomer(orderBean);
			if (status) {
				return OrderNaoConstants.RETURN_STATUS_SUCCESS;
			} else {
				return OrderNaoConstants.RETURN_STATUS_FAIL;
			}
		} catch (Exception e) {
			logger.error("Exception :- " + e);
			return OrderNaoConstants.RETURN_STATUS_FAIL;
		}

	}

	@RequestMapping(OrderNaoConstants.PATH_SAVE_NEW_ORDER_FOR_EXISTING_CUSTOMER)
	@ResponseBody
	public String saveNewOrderForExistingCustomer(
			@ModelAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ORDERBEAN) OrderBean orderBean, HttpSession session) {
		logger.info("Entry at saveNewOrderForExistingCustomer(Controller) ");
		logger.info("Order Length :- " + orderBean.getTotalNumberOfOrders());
		String contactNumber = (String) session.getAttribute(OrderNaoConstants.SESSION_ATTRIBUTE_CONTACT_NUMBER);
		orderBean.setCustomerPhone(contactNumber);
		String itemName = (String) orderBean.getItemName();
		String orderPickedFrom = (String) orderBean.getOrderPickedFrom();
		String orderDeliveredAt = (String) orderBean.getOrderDeliveredAt();
		int totalDistance = orderBean.getTotalDistance();
		double serviceCharge = orderBean.getServiceCharge();
		if (itemName == null || itemName.isEmpty()) {
			return OrderNaoConstants.RETURN_STATUS_EMPTY_ITEM;
		} else if (orderPickedFrom == null || orderPickedFrom.isEmpty()) {
			return OrderNaoConstants.RETURN_STATUS_EMPTY_PICKUP_LOCATION;
		} else if (orderDeliveredAt == null || orderDeliveredAt.isEmpty()) {
			return OrderNaoConstants.RETURN_STATUS_EMPTY_DELIVERY_LOCATION;
		} else if (totalDistance < 0) {
			return OrderNaoConstants.RETURN_STATUS_INCORRECT_DISTANCE;
		} else if (serviceCharge < 0) {
			return OrderNaoConstants.RETURN_STATUS_INCORRECT_SERVICE_CHARGE;
		}

		try {
			boolean status = service.insertOrderDetails(orderBean);
			if (status) {
				logger.info("Exit at saveNewOrderForExistingCustomer(Controller) ");
				return OrderNaoConstants.RETURN_STATUS_SUCCESS;
			} else {
				logger.info("Exit at saveNewOrderForExistingCustomer(Controller) ");
				return OrderNaoConstants.RETURN_STATUS_FAIL;
			}
		} catch (Exception e) {
			logger.error("Exception :- " + e);
			return OrderNaoConstants.RETURN_STATUS_FAIL;
		}

	}

	/**
	 * @author Shubham Sharma
	 * @Date 04-Nov-2017
	 * @Time 12:33:03 PM
	 * @Description this method is used to add
	 *              employee(Call_Operator,Manager,Delivery_Boys)
	 * @Return success if employee is added & error if any error is occured
	 */
	@RequestMapping(OrderNaoConstants.PATH_ADD_EMPLOYEE)
	@ResponseBody
	public String addEmployee(@ModelAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_EMPLOYEE_BEAN) EmployeeBean employee) {
		logger.info("Entry at addEmployee");
		String userName = employee.getUserName();
		String firstName = employee.getFirstName();
		String lastName = employee.getLastName();
		String password = employee.getPassword();
		String confirmPassword = employee.getConfirmPassword();
		String employeeType = employee.getEmployeeType();
		String contactNumber = employee.getContactNumber();
		logger.info(userName + " " + firstName + " " + lastName + " " + password + " " + confirmPassword + " "
				+ employeeType + " " + contactNumber);
		if (userName == null || userName.isEmpty()) {
			return OrderNaoConstants.RETURN_STATUS_EMPTY_USERNAME;
		} else if (firstName == null || firstName.isEmpty()) {
			return OrderNaoConstants.RETURN_STATUS_EMPTY_FIRSTNAME;
		} else if (lastName == null || lastName.isEmpty()) {
			return OrderNaoConstants.RETURN_STATUS_EMPTY_LASTNAME;
		} else if (contactNumber.length() < 0 && contactNumber.length() > OrderNaoConstants.MAX_MOBILE_NUMBER_LENGTH) {
			return OrderNaoConstants.RETURN_STATUS_INVALID_CONTACT_NUMBER;
		} else if (password == null || password.isEmpty()) {
			return OrderNaoConstants.RETURN_STATUS_EMPTY_PASSWORD;
		} else if (confirmPassword == null || confirmPassword.isEmpty()) {
			return OrderNaoConstants.RETURN_STATUS_EMPTY_CONFIRM_PASSWORD;
		} else if (!password.equals(confirmPassword)) {
			return OrderNaoConstants.RETURN_STATUS_PASSWORD_DOESNOT_MATCH;
		}
		// Here we check whether username exist in database if exist we return
		// "username exist" else we process the request
		boolean usernameStatus = service.checkForUserName(userName);
		if (usernameStatus) {
			logger.info("Username Exists");
			logger.info("Exit at addEmployee(Controller) ");
			return OrderNaoConstants.RETURN_STATUS_USERNAME_NOT_AVAILABLE;
		}
		// Here we check whether contact number exist in database if exist we
		// return
		// "phone number exist " else we process the request
		boolean contactNumberStatus = service.checkForPhoneNumber(contactNumber);
		if (contactNumberStatus) {
			logger.info("Contact Number Exists");
			logger.info("Exit at addEmployee");
			return OrderNaoConstants.RETURN_STATUS_PHONE_NUMBER_NOT_AVAILABLE;
		}
		boolean status = service.saveEmployee(employee);
		if (status) {
			logger.info("Employee Inserted successfully ");
			logger.info("Exit at addEmployee ");
			return OrderNaoConstants.RETURN_STATUS_SUCCESS;
		}
		logger.info("Employee Insertion failed ");
		logger.info("Exit at addEmployee ");
		return OrderNaoConstants.RETURN_STATUS_FAIL;

	}

	// here we are fetching more details for multiple orders
	@RequestMapping(value = OrderNaoConstants.PATH_MORE_DETAILS_OF_ORDER)
	public String getMoreDetailOfOrder(@RequestParam(OrderNaoConstants.REQUEST_PARAM_ORDERNUMBER) int orderNumber,
			Model model) {
		logger.info("Entry at getMoreDetailOfOrder(Controller)");
		logger.info("Order Number :- " + orderNumber);
		List<OrderBean> moreDetailsOfOrderList = service.getMoreDetailOfOrder(orderNumber);
		model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_MORE_DETAIL_OF_ORDER, moreDetailsOfOrderList);
		logger.info("Exit at getMoreDetailOfOrder(Controller)");
		return OrderNaoConstants.RETURN_STATUS_MORE_DETAILS_OF_ORDER;
	}

	// This method is used to assign order to delivery boy
	@RequestMapping(value = OrderNaoConstants.PATH_ASSIGN_ORDER_TO_DELIVERY_BOY, method = RequestMethod.POST)
	public String assignOrderToDeliveryBoy(@RequestParam(OrderNaoConstants.REQUEST_PARAM_STATUS) String status,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_DATE) String date,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_ASSIGNMENT) String assignment,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_DELIVERY_BOYID) int deliveryBoyId,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_ORDERNUMBER) int orderNumber, Model model) {
		logger.info("Entry at assignOrderToDeliveryBoy(Controller) Deliveryboyid :- " + deliveryBoyId);
		logger.info("status :- " + status + " date :- " + date + " assignment :- " + assignment);

		String returnMessage = service.deliveryBoyOrderAssignment(deliveryBoyId, orderNumber);
		if (returnMessage.equalsIgnoreCase(OrderNaoConstants.RETURN_STATUS_SUCCESS)) {
			logger.info("Exit at assignOrderToDeliveryBoy(Controller) ");
			logger.info("Redirecting Request (Controller)");
			return "redirect:/filter-track-order?status=" + status + "&date=" + date + "&assignment=" + assignment;
		} else if (returnMessage.equalsIgnoreCase(OrderNaoConstants.RETURN_STATUS_ERROR)) {
			logger.info("Error(Controller)");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.ERROR_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE, OrderNaoConstants.ERROR_MSG);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		} else {
			logger.info("Suspicious Activity found(Controller)");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		}

	}

	@RequestMapping(value = OrderNaoConstants.PATH_TRACK_DELIVERY_HTML_PAGE)
	public String trackDelivery(HttpServletRequest request, HttpServletResponse response, Model model,
			HttpSession session) {
		logger.info("Entry at trackDelivery(Controller)");
		session.removeAttribute(OrderNaoConstants.SESSION_ATTRIBUTE_SEARCH_KEY);
		List<OrderBean> orderBeanList = service.getOrderDetailsOfCustomer();
		List<OrderBean> deliveryBoysList = service.getDeliveryBoysList();
		model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TRACK_ORDER_BEAN, orderBeanList);
		model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_DELIVERY_BOYS_BEAN, deliveryBoysList);
		logger.info("Exit at trackDelivery(Controller)");
		return OrderNaoConstants.PATH_TRACK_DELIVERY_PAGE;
	}

	// This method is used to filter track order by status
	@RequestMapping(value = OrderNaoConstants.PATH_FILTER_TRACK_ORDER)
	public String filterTrackOrder(@RequestParam(OrderNaoConstants.REQUEST_PARAM_STATUS) String status,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_DATE) String date,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_ASSIGNMENT) String assignment, Model model,
			HttpSession session) {
		logger.info("Entry at filterTrackOrder(Controller) ");
		logger.info("Status :- " + status + " Date :- " + date + " Assignment :- " + assignment);
		// this is used for search if search is not null it means the last
		// request is of search
		// else it is other request
		String searchKey = null;
		if (session.getAttribute(OrderNaoConstants.SESSION_ATTRIBUTE_SEARCH_KEY) != null) {
			searchKey = (String) session.getAttribute(OrderNaoConstants.SESSION_ATTRIBUTE_SEARCH_KEY);
		}
		List<OrderBean> filterOrderList = service.filterTrackOrder(status, date, assignment, searchKey);
		List<OrderBean> deliveryBoysList = service.getDeliveryBoysList();
		model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TRACK_ORDER_BEAN, filterOrderList);
		model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_DELIVERY_BOYS_BEAN, deliveryBoysList);
		logger.info("Exit at filterTrackOrder(Controller) ");
		return OrderNaoConstants.PATH_FRAGMENTS_TRACK_DELIVERY_TABLE;
	}

	/*
	 * // This method is used to filter track order by Date
	 * 
	 * @RequestMapping(value = OrderNaoConstants.PATH_FILTER_ORDER_BY_DATE)
	 * public String
	 * filterOrdersByDate(@RequestParam(OrderNaoConstants.REQUEST_PARAM_DATE)
	 * String date, Model model, HttpSession session) {
	 * logger.info("Entry at filterOrdersByDate(Controller) Date : - " + date);
	 * if ((date != null && date.trim().length() > 0) &&
	 * (date.equalsIgnoreCase(OrderNaoConstants.ORDER_DATE_TODAY) ||
	 * date.equalsIgnoreCase(OrderNaoConstants.ORDER_DATE_LAST_SEVEN_DAYS) ||
	 * date.equalsIgnoreCase(OrderNaoConstants.ORDER_DATE_THIS_MONTH) ||
	 * date.equalsIgnoreCase(OrderNaoConstants.ORDER_DATE_TILL_DATE))) {
	 * 
	 * if (session.getAttribute(OrderNaoConstants.
	 * SESSION_ATTRIBUTE_FILTER_ORDER_STATUS) != null) { // if filter order by
	 * status is not null then we filter orders // using this priority // 1)By
	 * status 2)By time & we store filter ordder by time in // session it will
	 * be used in filter order by // assignment(DeliveryBoys)
	 * session.setAttribute(OrderNaoConstants.
	 * SESSION_ATTRIBUTE_FILTER_ORDER_TIME, date); String status = (String)
	 * session.getAttribute(OrderNaoConstants.
	 * SESSION_ATTRIBUTE_FILTER_ORDER_STATUS); List<OrderBean> filterOrderList =
	 * service.filterOrdersByStatusAndTime(date, status); List<OrderBean>
	 * deliveryBoysList = service.getDeliveryBoysList();
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TRACK_ORDER_BEAN,
	 * filterOrderList);
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_DELIVERY_BOYS_BEAN,
	 * deliveryBoysList); logger.info("List Size :- " + filterOrderList.size());
	 * logger.info("Exit at filterOrdersByDate(Controller)"); return
	 * OrderNaoConstants.PATH_FRAGMENTS_TRACK_DELIVERY_TABLE;
	 * 
	 * } else { // here filter order by status is null the we filter order //
	 * directly by time List<OrderBean> filterOrderList =
	 * service.filterOrdersByDate(date); List<OrderBean> deliveryBoysList =
	 * service.getDeliveryBoysList();
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TRACK_ORDER_BEAN,
	 * filterOrderList);
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_DELIVERY_BOYS_BEAN,
	 * deliveryBoysList); logger.info("List Size :- " + filterOrderList.size());
	 * logger.info("Exit at filterOrdersByDate(Controller)"); return
	 * OrderNaoConstants.PATH_FRAGMENTS_TRACK_DELIVERY_TABLE; } } else {
	 * logger.info("Suspicious Activity found.");
	 * model.addAttribute(OrderNaoConstants.
	 * MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
	 * OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG_HEADER);
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
	 * OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG); return
	 * OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY; } }
	 * 
	 * @RequestMapping(value =
	 * OrderNaoConstants.PATH_FILTER_ORDER_BY_ASSIGNMENT) public String
	 * filterOrdersByAssignment(@RequestParam(OrderNaoConstants.
	 * REQUEST_PARAM_ASSIGNMENT) String assignment, Model model, HttpSession
	 * session) { logger.
	 * info("Entry at filterOrdersByAssignment(Controller) order assignment status :- "
	 * + assignment);
	 * 
	 * // here we are checking for null and length and whether assignment value
	 * // contains(assigned or unassigned) or not // if it doesn't satisfied the
	 * value the we will return suspicious // activity found if ((assignment !=
	 * null && assignment.trim().length() > 0) &&
	 * (assignment.equalsIgnoreCase(OrderNaoConstants.ORDER_ASSIGNED) ||
	 * assignment.equalsIgnoreCase(OrderNaoConstants.ORDER_UNASSIGNED))) { //
	 * here we filter order based on priority // 1)ByStatus 2)ByTime
	 * 3)ByAssignment if (session.getAttribute(OrderNaoConstants.
	 * SESSION_ATTRIBUTE_FILTER_ORDER_STATUS) != null) { // if status is not
	 * null then we fetch status from session String status = (String)
	 * session.getAttribute(OrderNaoConstants.
	 * SESSION_ATTRIBUTE_FILTER_ORDER_STATUS); if
	 * (session.getAttribute(OrderNaoConstants.
	 * SESSION_ATTRIBUTE_FILTER_ORDER_TIME) != null) { // if time is not null
	 * the we fetch time from session String time = (String)
	 * session.getAttribute(OrderNaoConstants.
	 * SESSION_ATTRIBUTE_FILTER_ORDER_TIME); // here we filter orders
	 * ByStatus,ByTime and ByAssignment List<OrderBean> filterOrderList =
	 * service.filterOrdersByStatusAndTimeAndAssignment(status, time,
	 * assignment); List<OrderBean> deliveryBoysList =
	 * service.getDeliveryBoysList();
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TRACK_ORDER_BEAN,
	 * filterOrderList);
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_DELIVERY_BOYS_BEAN,
	 * deliveryBoysList); logger.info(" List Size :- " +
	 * filterOrderList.size());
	 * logger.info("Exit at filterOrdersByAssignment(Controller)"); return
	 * OrderNaoConstants.PATH_FRAGMENTS_TRACK_DELIVERY_TABLE; } else { // here
	 * we filter orders Only ByStatus and ByAssignment List<OrderBean>
	 * filterOrderList = service.filterOrdersByStatusAndAssignment(status,
	 * assignment); List<OrderBean> deliveryBoysList =
	 * service.getDeliveryBoysList();
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TRACK_ORDER_BEAN,
	 * filterOrderList);
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_DELIVERY_BOYS_BEAN,
	 * deliveryBoysList); logger.info(" List Size :- " +
	 * filterOrderList.size());
	 * logger.info("Exit at filterOrdersByAssignment(Controller)"); return
	 * OrderNaoConstants.PATH_FRAGMENTS_TRACK_DELIVERY_TABLE; } } else if
	 * (session.getAttribute(OrderNaoConstants.
	 * SESSION_ATTRIBUTE_FILTER_ORDER_TIME) != null) { // here we filter orders
	 * by time and assigment String time = (String)
	 * session.getAttribute(OrderNaoConstants.
	 * SESSION_ATTRIBUTE_FILTER_ORDER_TIME); List<OrderBean> filterOrderList =
	 * service.filterOrdersByTimeAndAssignment(time, assignment);
	 * List<OrderBean> deliveryBoysList = service.getDeliveryBoysList();
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TRACK_ORDER_BEAN,
	 * filterOrderList);
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_DELIVERY_BOYS_BEAN,
	 * deliveryBoysList); logger.info(" List Size :- " +
	 * filterOrderList.size());
	 * logger.info("Exit at filterOrdersByAssignment(Controller)"); return
	 * OrderNaoConstants.PATH_FRAGMENTS_TRACK_DELIVERY_TABLE;
	 * 
	 * } else { // here both time and status is null so we filter orders only by
	 * // assignment List<OrderBean> filterOrderList =
	 * service.filterOrdersByAssignment(assignment); List<OrderBean>
	 * deliveryBoysList = service.getDeliveryBoysList();
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TRACK_ORDER_BEAN,
	 * filterOrderList);
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_DELIVERY_BOYS_BEAN,
	 * deliveryBoysList); logger.info("List Size :- " + filterOrderList.size());
	 * logger.info("Exit at filterOrdersByAssignment(Controller)"); return
	 * OrderNaoConstants.PATH_FRAGMENTS_TRACK_DELIVERY_TABLE; }
	 * 
	 * } else { logger.info("Suspicious Activity found.");
	 * model.addAttribute(OrderNaoConstants.
	 * MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
	 * OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG_HEADER);
	 * model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
	 * OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG); return
	 * OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY; } }
	 */
	@RequestMapping(value = OrderNaoConstants.PATH_TRACK_DELIVERY_SEARCH, method = RequestMethod.POST)
	public String searchTrackDelivery(@RequestParam(OrderNaoConstants.REQUEST_PARAM_SEARCH_KEY) String searchKey,
			Model model, HttpSession session) {
		logger.info("Entry at searchTrackDelivery(Controller) search key:- " + searchKey);
		session.setAttribute(OrderNaoConstants.SESSION_ATTRIBUTE_SEARCH_KEY, searchKey);
		List<OrderBean> searchOrderList = service.searchTrackDelivery(searchKey);
		List<OrderBean> deliveryBoysList = service.getDeliveryBoysList();
		model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TRACK_ORDER_BEAN, searchOrderList);
		model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_DELIVERY_BOYS_BEAN, deliveryBoysList);
		logger.info(" Search List Size :- " + searchOrderList.size());
		logger.info("Exit at searchTrackDelivery(Controller)");
		return OrderNaoConstants.PATH_FRAGMENTS_TRACK_DELIVERY_TABLE;
	}

	@RequestMapping(value = OrderNaoConstants.PATH_COMMENTS_OF_FAILED_STATUS)
	public String getCommentsOfFailedOrder(
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_ORDERNUMBER) String orderNumber, Model model) {
		logger.info("Entry at getCommentsOfFailedOrder(Controller) orderNumber:- " + orderNumber);
		boolean status = service.checkForOrderNumberAndFailedStatus(orderNumber);
		if (status) {
			OrderBean failedOrderCommentsBean = service.getCommentsOfFailedOrder(orderNumber);
			model.addAttribute("failedOrderBean", failedOrderCommentsBean);
			logger.info("Exit at getCommentsOfFailedOrder(Controller)");
			return OrderNaoConstants.PATH_FRAGMENTS_FAILED_ORDER_DETAILS;
		} else {
			logger.info("Suspicious Activity found.");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		}
	}

	/*
	 * @RequestMapping(value = OrderNaoConstants.PATH_ORDER_STATUS_MODAL)
	 * 
	 * @ResponseBody public String
	 * showOrderStatusModal(@RequestParam(OrderNaoConstants.
	 * REQUEST_PARAM_ORDERNUMBER) String orderNumber,
	 * 
	 * @RequestParam(OrderNaoConstants.REQUEST_PARAM_NEW_STATUS_OF_ORDER) String
	 * newStatusOfOrder, HttpSession session) {
	 * session.setAttribute(OrderNaoConstants.
	 * SESSION_ATTRIBUTE_NEW_ORDER_STATUS, newStatusOfOrder);
	 * session.setAttribute(OrderNaoConstants.SESSION_ATTRIBUTE_ORDER_NUMBER,
	 * orderNumber); logger.info( "showOrderStatusModal Order Number :- " +
	 * orderNumber + " New status of order :- " + newStatusOfOrder); return
	 * OrderNaoConstants.RETURN_STATUS_SUCCESS; }
	 */

	@RequestMapping(value = OrderNaoConstants.PATH_SAVE_FAILED_STATUS_COMMENT, method = RequestMethod.POST)
	public String saveFailedStatusCommentsOfOrder(@RequestParam(OrderNaoConstants.REQUEST_PARAM_STATUS) String status,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_DATE) String date,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_ASSIGNMENT) String assignment,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_ORDERNUMBER) int orderNumber,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_NEW_STATUS) String newStatusOfOrder,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_FAILED_STATUS_COMMENTS) String failedComments, Model model) {
		logger.info("Entry at saveFailedStatusCommentsOfOrder(Controller) ");
		logger.info("status :-" + status + " date :- " + date + " assignment :- " + assignment + " orderNumber :- "
				+ orderNumber + " New Status :- " + newStatusOfOrder + "	Failed Comments :- " + failedComments);
		String returnMessage = service.savePendingOrDeliveredOrFailedOrder(orderNumber, newStatusOfOrder,
				failedComments);
		if (returnMessage.equals(OrderNaoConstants.RETURN_STATUS_SUCCESS)) {
			logger.info("Forwarding request(Controller) ");
			logger.info("Exit at saveFailedStatusCommentsOfOrder(Controller) ");
			return "redirect:/filter-track-order?status=" + status + "&date=" + date + "&assignment=" + assignment;
		} else if (returnMessage.equals(OrderNaoConstants.RETURN_STATUS_ERROR)) {
			logger.info("Exit at saveFailedStatusCommentsOfOrder(Controller) ");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.ERROR_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE, OrderNaoConstants.ERROR_MSG);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		} else {
			logger.info("Exit at saveFailedStatusCommentsOfOrder(Controller) ");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		}

	}

	@RequestMapping(value = OrderNaoConstants.PATH_SAVE_PENDING_OR_DELIVERED_ORDER_STATUS)
	public String savePendingOrDeliveredStatusCommentsOfOrder(
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_STATUS) String status,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_DATE) String date,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_ASSIGNMENT) String assignment,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_ORDERNUMBER) int orderNumber,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_NEW_STATUS) String newStatus, Model model) {
		logger.info("Entry at savePendingOrDeliveredStatusOfOrder(Controller) ");
		logger.info("status :-" + status + " date :- " + date + " assignment :- " + assignment + " orderNumber :- "
				+ orderNumber + " New Status :- " + newStatus);
		String failedStatus = "";
		String returnMessage = service.savePendingOrDeliveredOrFailedOrder(orderNumber, newStatus, failedStatus);
		if (returnMessage.equals(OrderNaoConstants.RETURN_STATUS_SUCCESS)) {
			logger.info("Forwarding request(Controller) ");
			logger.info("Exit at savePendingOrDeliveredStatusOfOrder(Controller) ");
			return "redirect:/filter-track-order?status=" + status + "&date=" + date + "&assignment=" + assignment;
		} else if (returnMessage.equals(OrderNaoConstants.RETURN_STATUS_ERROR)) {
			logger.info("Exit at savePendingOrDeliveredStatusOfOrder(Controller) ");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.ERROR_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE, OrderNaoConstants.ERROR_MSG);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		} else if (returnMessage.equals(OrderNaoConstants.DELIVERY_BOY_NOT_ASSIGNED)) {
			logger.info("Exit at savePendingOrDeliveredStatusOfOrder(Controller) ");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.ERROR_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
					OrderNaoConstants.ERROR_MSG_DELIVERY_BOY_NOT_ASSIGNED);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		} else {
			logger.info("Exit at savePendingOrDeliveredStatusOfOrder(Controller) ");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		}
	}

	/**
	 * @author shubham sharma
	 * @date 29-Oct-2017
	 * @time 10:05:33 PM
	 * @description it is called for submissionreports.html
	 * @return list of delivery boys & total money to be collected(current day
	 *         wise)
	 */
	@RequestMapping(value = OrderNaoConstants.PATH_SUBMIT_REPORT_HTML)
	public String getSubmittionReports(Model model) {
		logger.info("Entry at getSubmittionReports(Controller)");
		List<OrderBean> deliveryBoysList = service.getDeliveryBoysList();
		double moneyToBeCollected = service.getTotalMoneyToBeCollected();
		double totalMoneyCollected = service.getTotalMoneyCollected();
		model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TOTAL_MONEY_COLLECTED, totalMoneyCollected);
		model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TOTAL_MONEY_TO_BE_COLLECTED, moneyToBeCollected);
		model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_DELIVERY_BOYS_BEAN, deliveryBoysList);
		logger.info("Exit at getSubmittionReports(Controller)");
		return OrderNaoConstants.PATH_SUBMITTION_REPORTS;
	}

	/**
	 * @author shubham sharma
	 * @date 30-Oct-2017
	 * @time 3:16:26 PM
	 * @description this function is called when delivery boy is selected from
	 *              drop down at submission reports
	 * @return
	 */
	@RequestMapping(value = OrderNaoConstants.PATH_DELIVERY_BOY_PAYMENT_DETAILS)
	public String getDeliveryBoyPaymentDetails(
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_DELIVERY_BOY_ID) int deliveryBoyId, Model model) {
		logger.info("Entry at getDeliveryBoyPaymentDetails(Controller)");
		/*
		 * Here we are checking for delivery boys in users & roles table if
		 * delivery boy exist then we continue otherwise we return suspicious
		 * activity
		 */
		boolean deliveryBoyStatus = service.checkDeliveryBoy(deliveryBoyId);
		if (deliveryBoyStatus) {
			// Here we are fetching delivery boy payment details
			DeliveryBoyPaymentBean paymentBean = service.getDeliveryBoyPaymentDetails(deliveryBoyId);
			/*
			 * Here we are calculating total submission it is sum of
			 * money_provided_in_morning and
			 * total_service_charge_to_be_collected
			 */
			double totalSubmission = paymentBean.getTotalMoneyProvidedInMorning()
					+ paymentBean.getTotalServiceChargeToCollect();
			logger.info(
					"Total Submission :- " + totalSubmission + " MoneyCollected :- " + paymentBean.getMoneyCollected());
			if (totalSubmission == paymentBean.getMoneyCollected()) {
				/*
				 * if totalSubmission equals to moneyCollectedFromDeliveryBoy
				 * then we hide submit money button from delivery boy & show
				 * Already submitted button
				 */
				logger.info("Money Already Collected From Delivery Boy");
				model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_MONEY_ALREADY_SUBMITTED, true);
			} else {
				model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_MONEY_ALREADY_SUBMITTED, false);
			}
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TOTAL_SUBMISSION, totalSubmission);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_DELIVERY_BOY_TRANSACTION_DETAILS, paymentBean);
			logger.info("Exit at getDeliveryBoyPaymentDetails(Controller):Success");
			return OrderNaoConstants.PATH_FRAGMENTS_DELIVERY_BOY_TRANSACTION;
		} else {
			logger.info("Exit at getDeliveryBoyPaymentDetails(Controller):SuspiciousActivity");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		}

	}

	/**
	 * @author shubham sharma
	 * @date 29-Oct-2017
	 * @time 10:26:48 PM
	 * @description this method will update money provided to delivery boy
	 * @return suspicious activity in case of error,updated payment details of
	 *         delivery boy & also return new value of Total money to collect
	 */
	@RequestMapping(value = OrderNaoConstants.PATH_UPDATE_MONEY_PROVIDED_TO_DELIVERY_BOY)
	public String updateDeliveryBoyMoneyProvided(
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_DELIVERY_BOY_ID) int deliveryBoyId,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_MONEY_PROVIDED) double moneyProvidedInMorning, Model model) {
		logger.info("Entry at updateDeliveryBoyMoneyProvided(Controller)");
		/*
		 * Here we are checking for delivery boys in users & roles table if
		 * delivery boy exist then we continue otherwise we return suspicious
		 * activity
		 */if (moneyProvidedInMorning > 0) {
			boolean deliveryBoyStatus = service.checkDeliveryBoy(deliveryBoyId);
			if (deliveryBoyStatus) {
				boolean moneyProvidedUpdateStatus = service.updateDeliveryBoyMoneyProvided(deliveryBoyId,
						moneyProvidedInMorning);
				if (moneyProvidedUpdateStatus) {
					// Here we are fetching delivery boy payment details
					DeliveryBoyPaymentBean paymentBean = service.getDeliveryBoyPaymentDetails(deliveryBoyId);
					/*
					 * Here we are calculating total submission it is sum of
					 * money_provided_in_morning and
					 * total_service_charge_to_be_collected
					 */
					double totalSubmission = paymentBean.getTotalMoneyProvidedInMorning()
							+ paymentBean.getTotalServiceChargeToCollect();
					logger.info("Total Submission :- " + totalSubmission + " MoneyCollected :- "
							+ paymentBean.getMoneyCollected());
					if (totalSubmission == paymentBean.getMoneyCollected()) {
						/*
						 * if totalSubmission equals to
						 * moneyCollectedFromDeliveryBoy then we hide submit
						 * money button from delivery boy & show Already
						 * submitted button
						 */
						logger.info("Money Already Collected From Delivery Boy");
						model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_MONEY_ALREADY_SUBMITTED, true);
					} else {
						model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_MONEY_ALREADY_SUBMITTED, false);
					}
					model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TOTAL_SUBMISSION, totalSubmission);
					model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_DELIVERY_BOY_TRANSACTION_DETAILS, paymentBean);
					logger.info("Exit at updateDeliveryBoyMoneyProvided(Controller):Success");
					return OrderNaoConstants.PATH_FRAGMENTS_DELIVERY_BOY_TRANSACTION;
				} else {
					logger.info("Exit at updateDeliveryBoyMoneyProvided(Controller):SuspiciousActivity");
					model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
							OrderNaoConstants.ERROR_MSG_HEADER);
					model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE, OrderNaoConstants.ERROR_MSG);
					return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
				}
			} else {
				logger.info("Exit at updateDeliveryBoyMoneyProvided(Controller):SuspiciousActivity");
				model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
						OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG_HEADER);
				model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
						OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG);
				return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
			}
		} else {
			logger.info("Exit at updateDeliveryBoyMoneyProvided(Controller):Value of Money Provided is less than zero");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.ERROR_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE, OrderNaoConstants.VALUE_LESS_THAN_ZERO);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		}

	}

	/**
	 * @author shubham sharma
	 * @date 29-Oct-2017
	 * @time 11:26:35 PM
	 * @description this method will fetch delivery boy trip details(orders done
	 *              by delivery boys)
	 * @return delivery boy trip details
	 */
	@RequestMapping(value = OrderNaoConstants.PATH_DELIVERY_BOY_TRIP_DETAILS)
	public String getDeliveryBoyTripDetails(
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_DELIVERY_BOY_ID) int deliveryBoyId, Model model) {
		logger.info("Entry at getDeliveryBoyTripDetails(Controller)");
		/*
		 * Here we are checking for delivery boys in users & roles table if
		 * delivery boy exist then we continue otherwise we return suspicious
		 * activity
		 */
		boolean deliveryBoyStatus = service.checkDeliveryBoy(deliveryBoyId);
		if (deliveryBoyStatus) {
			List<OrderBean> ordersAssignedToDeliveryBoy = service.getDeliveryBoyTripDetails(deliveryBoyId);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ORDER_ASSIGNED_TO_DELIVERY_BOYS,
					ordersAssignedToDeliveryBoy);
			logger.info("Exit at getDeliveryBoyTripDetails(Controller)");
			return OrderNaoConstants.PATH_FRAGMENTS_DELIVERY_BOY_TRIP_DETAILS;

		} else {
			logger.info("Exit at getDeliveryBoyTripDetails(Controller):SuspiciousActivity");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		}

	}

	/**
	 * @author shubham sharma
	 * @date 30-Oct-2017
	 * @time 4:53:03 PM
	 * @description it will update money submitted by delivery boy in db
	 * @return
	 */
	@RequestMapping(value = OrderNaoConstants.PATH_UPDATE_MONEY_SUBMITTED_BY_DELIVERY_BOY, method = RequestMethod.POST)
	public String updateMoneySubmittedByDeliveryBoy(
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_DELIVERY_BOY_ID) int deliveryBoyId,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_SUBMITTED_MONEY_COMMENTS) String comments, Model model) {
		logger.info("Entry at updateMoneySubmittedByDeliveryBoy(Controller)");
		/*
		 * Here we are checking for delivery boys in users & roles table if
		 * delivery boy exist then we continue otherwise we return suspicious
		 * activity
		 */

		if (comments != null && comments.trim().length() > 0) {
			boolean deliveryBoyStatus = service.checkDeliveryBoy(deliveryBoyId);
			if (deliveryBoyStatus) {
				/*
				 * Here we are fetching total_money_provided_in_morning &
				 * total_service_charge_that_will_be_collected_by_delivery_by
				 * and add both of them to get
				 * totalMoneyThatDeliveryBoyWillSubmit
				 */
				DeliveryBoyPaymentBean paymentBean = service.getDeliveryBoyPaymentDetails(deliveryBoyId);
				double totalMoneyThatDeliveryBoyWillSubmit = paymentBean.getTotalMoneyProvidedInMorning()
						+ paymentBean.getTotalServiceChargeToCollect();

				if (totalMoneyThatDeliveryBoyWillSubmit != paymentBean.getMoneyCollected()) {
					boolean submittedMoneyStatus = service.updateMoneySubmittedByDeliveryBoy(deliveryBoyId, comments,
							totalMoneyThatDeliveryBoyWillSubmit);
					if (submittedMoneyStatus) {
						// Here again we are fetching delivery boy
						// details(updated
						// details)
						paymentBean = service.getDeliveryBoyPaymentDetails(deliveryBoyId);
						double totalSubmission = paymentBean.getTotalMoneyProvidedInMorning()
								+ paymentBean.getTotalServiceChargeToCollect();

						if (totalSubmission == paymentBean.getMoneyCollected()) {
							/*
							 * if totalSubmission equals to
							 * moneyCollectedFromDeliveryBoy then we hide submit
							 * money button from delivery boy & show Already
							 * submitted button
							 */
							logger.info("Money Already Collected From Delivery Boy");
							model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_MONEY_ALREADY_SUBMITTED, true);
						} else {
							model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_MONEY_ALREADY_SUBMITTED, false);
						}
						model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_TOTAL_SUBMISSION, totalSubmission);
						model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_DELIVERY_BOY_TRANSACTION_DETAILS,
								paymentBean);
						logger.info("Exit at updateMoneySubmittedByDeliveryBoy(Controller):Success");
						return OrderNaoConstants.PATH_FRAGMENTS_DELIVERY_BOY_TRANSACTION;
					} else {
						logger.info("Exit at updateMoneySubmittedByDeliveryBoy(Controller):SuspiciousActivity");
						model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
								OrderNaoConstants.ERROR_MSG_HEADER);
						model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
								OrderNaoConstants.ERROR_MSG);
						return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
					}
				} else {
					logger.info("Exit at updateMoneySubmittedByDeliveryBoy(Controller):SuspiciousActivity");
					model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
							OrderNaoConstants.ERROR_MSG_HEADER);
					model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
							OrderNaoConstants.NO_MONEY_TO_SUBMIT);
					return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
				}

			} else {
				logger.info("Exit at updateMoneySubmittedByDeliveryBoy(Controller):SuspiciousActivity");
				model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
						OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG_HEADER);
				model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
						OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG);
				return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
			}
		} else {
			logger.info(
					"Exit at updateMoneySubmittedByDeliveryBoy(Controller):Value of Money Provided is less than zero");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.ERROR_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE, OrderNaoConstants.EMPTY_COMMENTS);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		}

	}

	@RequestMapping(value = OrderNaoConstants.PATH_GET_MORE_DETAIL_OF_TRIP)
	public String getMoreDetailOfTrip(@RequestParam(OrderNaoConstants.REQUEST_PARAM_ORDERNUMBER) int orderNumber,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_DELIVERY_BOY_ID) int deliveryBoyId, Model model) {
		logger.info("Entry at getMoreDetailOfTrip(Controller)");
		/*
		 * Here we are checking for delivery boys in users & roles table if
		 * delivery boy exist then we continue otherwise we return suspicious
		 * activity
		 */
		boolean deliveryBoyStatus = service.checkDeliveryBoy(deliveryBoyId);
		if (deliveryBoyStatus) {
			List<OrderBean> ordersAssignedToDeliveryBoy = service.getDeliveryBoyTripMoreDetails(orderNumber,
					deliveryBoyId);
			for (OrderBean orderBean : ordersAssignedToDeliveryBoy) {
				logger.info("itemname :" + orderBean.getItemName());
				logger.info("pickup point :" + orderBean.getOrderPickedFrom());
				logger.info("delivery point :" + orderBean.getOrderDeliveredAt());
			}
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ORDER_ASSIGNED_TO_DELIVERY_BOYS,
					ordersAssignedToDeliveryBoy);
			logger.info("Exit at getMoreDetailOfTrip(Controller)");
			return OrderNaoConstants.PATH_FRAGMENTS_DELIVERY_BOY_TRIP_MORE_DETAILS;

		} else {
			logger.info("Exit at getMoreDetailOfTrip(Controller):SuspiciousActivity");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		}

	}

	@RequestMapping(value = OrderNaoConstants.PATH_REPORTS_HTML_PAGE)
	public String orderReports(Model model) {
		logger.info("Entry at orderReports()");
		int totalOrdersOfCurrentDate = service.getTotalOrderCountOfCurrentDate();
		int totalSuccessfullOfCurrentDate = service.getSuccessfullOrderCountOfCurrentDate();
		int totalFailedOfCurrentDate = service.getFailedOrderCountOfCurrentDate();

		int totalOrdersOfWeek = service.getTotalOrderCountOfWeek();
		int totalSuccessfullOfWeek = service.getSuccessfullOrderCountOfWeek();
		int totalFailedOfWeek = service.getFailedOrderCountOfWeek();

		model.addAttribute(OrderNaoConstants.MODEL_ATTRIBUTE_CURRENT_DATE_TOTAL_ORDERS, totalOrdersOfCurrentDate);
		model.addAttribute(OrderNaoConstants.MODEL_ATTRIBUTE_CURRENT_DATE_SUCCESSFULL_ORDERS,
				totalSuccessfullOfCurrentDate);
		model.addAttribute(OrderNaoConstants.MODEL_ATTRIBUTE_CURRENT_DATE_FAILED_ORDERS, totalFailedOfCurrentDate);
		model.addAttribute(OrderNaoConstants.MODEL_ATTRIBUTE_WEEK_TOTAL_ORDERS, totalOrdersOfWeek);
		model.addAttribute(OrderNaoConstants.MODEL_ATTRIBUTE_WEEK_SUCCESSFULL_ORDERS, totalSuccessfullOfWeek);
		model.addAttribute(OrderNaoConstants.MODEL_ATTRIBUTE_WEEK_FAILED_ORDERS, totalFailedOfWeek);
		logger.info("Exit at orderReports()");
		return OrderNaoConstants.PATH_REPORTS_PAGE;
	}

	@RequestMapping(value = OrderNaoConstants.PATH_MONTHLY_REPORT_OF_ORDER)
	public String monthlyReportOfOrders(Model model, @RequestParam int selectedMonth, @RequestParam int selectedYear) {
		logger.info("Entry at monthlyReportOfOrders()");
		int totalOrdersOfMonth = service.getTotalOrderCountOfMonth(selectedMonth, selectedYear);
		int totalSuccessfullOrdersOfMonth = service.getSuccessfullOrderCountOfMonth(selectedMonth, selectedYear);
		int totalFailedOrdersOfMonth = service.getFailedOrderCountOfMonth(selectedMonth, selectedYear);

		model.addAttribute(OrderNaoConstants.MODEL_ATTRIBUTE_MONTH_TOTAL_ORDERS, totalOrdersOfMonth);
		model.addAttribute(OrderNaoConstants.MODEL_ATTRIBUTE_MONTH_SUCCESSFULL_ORDERS, totalSuccessfullOrdersOfMonth);
		model.addAttribute(OrderNaoConstants.MODEL_ATTRIBUTE_MONTH_FAILED_ORDERS, totalFailedOrdersOfMonth);
		logger.info("Exit at monthlyReportOfOrders()");
		return OrderNaoConstants.PATH_FRAGMENTS_ORDERS_MONTHLY_STATUS;
	}

	@RequestMapping(value = OrderNaoConstants.PATH_GET_ORDER_REPORTS)
	public String orderReports(Model model, @RequestParam int forDate) {
		logger.info("Entry at orderReports() For Date :- " + forDate);
		List<OrderBean> moreDetaisOfOrderForReport = service.getMoreDetailsOfOrderForReport(forDate);
		if (moreDetaisOfOrderForReport != null) {
			logger.info("Order Report List(Size) :- " + moreDetaisOfOrderForReport.size());
		} else {
			logger.info("Order Report List(Size) :- null");
		}
		model.addAttribute(OrderNaoConstants.MODEL_ATTRIBUTE_DETILS_OF_ORDERS_FOR_REPORT, moreDetaisOfOrderForReport);
		logger.info("Exit at orderReports()");
		return OrderNaoConstants.PATH_ORDER_DETAIL_REPORTS_MODAL;
	}

	@RequestMapping(value = OrderNaoConstants.PATH_MONTHLY_ORDER_REPORTS)
	public String monthlyOrderReports(Model model, @RequestParam int forDate, @RequestParam int selectedYear,
			@RequestParam int selectedMonth) {
		logger.info("Entry at monthlyOrderReports() For Date :- " + forDate + " For Year :- " + selectedYear
				+ " For Month :- " + selectedMonth);
		List<OrderBean> monthlyOrderDetaisForReport = service.getMonthlyOrderDetailsForReport(forDate, selectedYear,
				selectedMonth);
		if (monthlyOrderDetaisForReport != null) {
			logger.info("Monthly Order Report List(Size) :- " + monthlyOrderDetaisForReport.size());
		} else {
			logger.info("Monthly Order Report List(Size) :- null");
		}
		model.addAttribute(OrderNaoConstants.MODEL_ATTRIBUTE_DETILS_OF_ORDERS_FOR_REPORT, monthlyOrderDetaisForReport);
		logger.info("Exit at monthlyOrderReports()");
		return OrderNaoConstants.PATH_ORDER_DETAIL_REPORTS_MODAL;
	}

	@RequestMapping(value = OrderNaoConstants.PATH_SAVE_PRODUCT_PRICE_OF_ORDER, method = RequestMethod.GET)
	public String saveProductPrice(@RequestParam(OrderNaoConstants.REQUEST_PARAM_STATUS) String status,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_DATE) String date,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_ASSIGNMENT) String assignment,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_ORDERNUMBER) int orderNumber,
			@RequestParam(OrderNaoConstants.REQUEST_PARAM_PRODUCT_PRICE) double productPrice, Model model) {
		logger.info("Entry at saveProductPrice productPrice :- " + productPrice + " orderNumber :- " + orderNumber);
		logger.info("status :- " + status + " date :- " + date + " assignment :- " + assignment);
		String returnMessage = service.saveProductPrice(orderNumber, productPrice);
		if (returnMessage.equalsIgnoreCase(OrderNaoConstants.RETURN_STATUS_SUCCESS)) {
			logger.info("Exit at saveProductPrice :Success");
			return "redirect:/filter-track-order?status=" + status + "&date=" + date + "&assignment=" + assignment;
		} else if (returnMessage.equalsIgnoreCase(OrderNaoConstants.RETURN_STATUS_PRODUCT_PRICE_LESS_THAN_ZERO)) {
			logger.info("Exit at saveProductPrice :Product price less than zero");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.ERROR_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
					OrderNaoConstants.ERROR_PRODUCT_PRICE_LESS_THAN_ZERO);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		} else if (returnMessage.equalsIgnoreCase(OrderNaoConstants.RETURN_STATUS_SUSPICIOUS_ACTIVITY)) {
			logger.info("Exit at saveProductPrice : Error");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE,
					OrderNaoConstants.SUSPICIOUS_ACTIVITY_MSG);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		} else {
			logger.info("Exit at saveProductPrice : Error");
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE_HEADER,
					OrderNaoConstants.ERROR_MSG_HEADER);
			model.addAttribute(OrderNaoConstants.MODAL_ATTRIBUTE_ERROR_MESSAGE, OrderNaoConstants.ERROR_MSG);
			return OrderNaoConstants.PATH_SUSPICIOUS_ACTIVITY;
		}
	}
}
