package com.ordernao.service;

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

import com.ordernao.bean.DeliveryBoyPaymentBean;
import com.ordernao.bean.EmployeeBean;
import com.ordernao.bean.OrderBean;
import com.ordernao.dao.OrderDao;
import com.ordernao.utility.OrderNaoConstants;
import com.ordernao.utility.Utility;

@Service
public class OrderService {
	static final Logger logger = LogManager.getLogger(OrderService.class.getName());
	@Autowired
	OrderDao dao;

	public OrderBean checkExistingCustomer(String contactNumber) {
		logger.info("Entry at checkExistingCustomer(Service)");
		OrderBean orderBean = new OrderBean();
		try {
			int result = dao.checkExistingCustomer(contactNumber);
			if (result > OrderNaoConstants.CUSTOMER_EXIST) {
				logger.info("Customer exist fetching customer details");
				orderBean = dao.getExistingCustomerInfo(contactNumber);
				orderBean.setNewCustomer(false);
			} else {
				logger.info("Customer doesn't exist");
				orderBean.setNewCustomer(true);
			}
			logger.info("Exit at checkExistingCustomer(Service)");
			return orderBean;
		} catch (Exception e) {
			logger.error("Exception :- ", e);
			return orderBean;
		}

	}

	public boolean saveNewCustomer(OrderBean orderBean) {
		logger.info("Entry at saveNewCustomer(Service)");
		boolean status = false;
		int customerStatus = dao.saveNewCustomerInfo(orderBean);
		if (customerStatus > 0) {
			status = insertOrderDetails(orderBean);
		}
		logger.info("Exit at saveNewCustomer(Service)");
		return status;
	}

	public boolean insertOrderDetails(OrderBean orderBean) {
		logger.info("Entry at insertOrderDetails(Service)");
		boolean status = false;
		String contactNumber = orderBean.getCustomerPhone();
		int id = dao.getCustomerIdFromContactNumber(contactNumber);
		orderBean.setCustomerId(id);
		String comments = orderBean.getComments();
		comments.replaceAll("\\s", "");
		if (!comments.isEmpty()) {
			logger.info("Comment Status :- Failed");
			orderBean.setCommentStatus(OrderNaoConstants.COMMENT_STATUS_FAILED);
		} else {
			logger.info("Comment Status :- N/A");
		}
		int orderStatus1 = dao.saveNewOrderInfoForCustomerInOrdersTable(orderBean);
		if (orderStatus1 > 0) {
			int orderNumber = dao.getOrderNumberFromClientId(id);
			int totalOrders = orderBean.getTotalNumberOfOrders();
			String[] itemNamesArray = Utility.getArrayFromString(orderBean.getItemName());
			String[] orderPickupPointsArray = Utility.getArrayFromString(orderBean.getOrderPickedFrom());
			String[] orderDeliveredAtArray = Utility.getArrayFromString(orderBean.getOrderDeliveredAt());
			if (totalOrders > 1) {
				// Here total order is number of pickup points and delivery
				// points
				// Multiple if totalOrders is > 1 else only one
				int[] mulipleOrderStatus = dao.saveMultipleOrders(orderBean, orderNumber, itemNamesArray,
						orderPickupPointsArray, orderDeliveredAtArray);
				if (mulipleOrderStatus.length > 1) {
					status = true;
				} else {
					status = false;
				}
			} else {
				int singleOrderStatus = dao.saveNewOrderInfoForCustomerInOrderDetailsTable(orderBean, orderNumber,
						itemNamesArray, orderPickupPointsArray, orderDeliveredAtArray);
				if (singleOrderStatus > 0) {
					status = true;
				} else {
					status = false;
				}
			}
		} else {
			status = false;
		}
		logger.info("Exit at saveNewCustomer(Service)");
		return status;
	}

	public OrderBean getNewCustomerInfo(String contactNumber) {
		logger.info("Entry at getNewCustomerInfo(Service)");
		logger.info("Exit at getNewCustomerInfo(Service)");
		return dao.getNewCustomerInfo(contactNumber);
	}

	public boolean saveEmployee(EmployeeBean employee) {
		logger.info("Entry at saveEmployee(Service)");
		boolean status = false;
		String employeeType = employee.getEmployeeType();
		logger.info("Employee Type :-(1-admin)(2-manager)(3-call operator)(4-delivery boy) " + employeeType);
		int employeeTypeId = OrderNaoConstants.INVALID_EMPLOYEE_TYPE;
		/*
		 * if (employeeType.equals(OrderNaoConstants.ADMIN)) { employeeTypeId =
		 * OrderNaoConstants.ADMIN_TYPE; } else
		 */if (employeeType.equals(OrderNaoConstants.MANAGER)) {
			employeeTypeId = OrderNaoConstants.MANAGER_TYPE;
		} else if (employeeType.equals(OrderNaoConstants.CALL_OPERATOR)) {
			employeeTypeId = OrderNaoConstants.CALL_OPERATOR_TYPE;
		} else if (employeeType.equals(OrderNaoConstants.DELIVERY_BOY)) {
			employeeTypeId = OrderNaoConstants.DELIVERY_BOY_TYPE;
		} else {
			return status;
		}

		try {
			int result = dao.saveEmployee(employee, employeeTypeId);
			if (result > 0) {
				logger.info("Employee inserted Successfully...");
				status = true;
			} else {
				status = false;
			}
			logger.info("Exit at saveEmployee(Service)");
			return status;
		} catch (Exception e) {
			logger.error("Exception :- " + e);
			return status;
		}

	}

	public boolean checkForUserName(String userName) {
		logger.info("Entry at checkForUserName");
		boolean status = false;
		try {
			int result = dao.checkForUserName(userName);
			logger.info("checkForUserName :- " + result);
			if (result > 0) {
				status = true;
			} else {
				status = false;
			}
			logger.info("Exit at checkForUserName");
			return status;
		} catch (Exception e) {
			logger.error("Exception " + e);
			return true;
		}

	}

	public List<OrderBean> getOrderDetailsOfCustomer() {
		return dao.getOrderDetailsOfCustomer();
	}

	public List<OrderBean> getDeliveryBoysList() {
		logger.info("Entry at getDeliveryBoysList");
		List<OrderBean> deliveryBoysList = new ArrayList<OrderBean>();
		try {
			deliveryBoysList = dao.getDeliveryBoysList();
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		logger.info("Exit at getDeliveryBoysList");
		return deliveryBoysList;
	}

	/*
	 * public boolean assignOrderToDeliveryBoy(int deliveryBoyId, int
	 * orderNumber) { logger.info("Entry at assignOrderToDeliveryBoy(Service)");
	 * boolean status = false; int result =
	 * dao.updateDeliveryBoyInOrdersTable(deliveryBoyId, orderNumber); if
	 * (result > 0) { status = true; }
	 * logger.info("Exit at assignOrderToDeliveryBoy(Service)"); return status;
	 * }
	 */

	public List<OrderBean> getMoreDetailOfOrder(int orderNumber) {
		logger.info("Entry at getMoreDetailOfOrder(Service)");
		List<OrderBean> moreDetailsOfOrderList = new ArrayList<OrderBean>();
		try {
			logger.info("Exit at getMoreDetailOfOrder(Service)");
			moreDetailsOfOrderList = dao.getMoreDetailOfOrder(orderNumber);
			return moreDetailsOfOrderList;
		} catch (Exception e) {
			logger.error("Exception :- " + e);
			return moreDetailsOfOrderList;
		}

	}

	/*
	 * public List<OrderBean> filterOrdersByStatus(String status) {
	 * logger.info("Entry at filterOrdersByStatus(Service)"); List<OrderBean>
	 * filteredOrderList = new ArrayList<OrderBean>(); try {
	 * logger.info("Exit at filterOrdersByStatus(Service)"); filteredOrderList =
	 * dao.filterOrdersByStatus(status); return filteredOrderList;
	 * 
	 * } catch (Exception e) { logger.error("Exception :- " + e); return
	 * filteredOrderList; } }
	 * 
	 * public List<OrderBean> filterOrdersByDate(String date) {
	 * logger.info("Entry at filterOrdersByDate(Service)"); List<OrderBean>
	 * filteredOrderList = new ArrayList<OrderBean>(); try {
	 * logger.info("Exit at filterOrdersByDate(Service)"); filteredOrderList =
	 * dao.filterOrdersByDate(date); return filteredOrderList;
	 * 
	 * } catch (Exception e) { logger.error("Exception :- " + e); return
	 * filteredOrderList; } }
	 * 
	 * public List<OrderBean> filterOrdersByAssignment(String assignment) {
	 * logger.info("Entry at filterOrdersByAssignment(Service)");
	 * List<OrderBean> filteredOrderList = new ArrayList<OrderBean>(); try {
	 * logger.info("Exit at filterOrdersByAssignment(Service)");
	 * filteredOrderList = dao.filterOrdersByAssignment(assignment); return
	 * filteredOrderList;
	 * 
	 * } catch (Exception e) { logger.error("Exception :- " + e); return
	 * filteredOrderList; } }
	 */

	public List<OrderBean> searchTrackDelivery(String searchKey) {
		logger.info("Entry at searchTrackDelivery(Service)");
		List<OrderBean> searchOrderList = new ArrayList<OrderBean>();
		try {
			logger.info("Exit at searchTrackDelivery(Service)");
			searchOrderList = dao.searchTrackDelivery(searchKey);
			return searchOrderList;

		} catch (Exception e) {
			logger.error("Exception :- " + e);
			return searchOrderList;
		}
	}

	public OrderBean getCommentsOfFailedOrder(String orderNumber) {
		logger.info("Entry at getCommentsOfFailedOrder(Service)");
		OrderBean bean = dao.getCommentsOfFailedOrder(orderNumber);
		logger.info("Exit at getCommentsOfFailedOrder(Service)");
		return bean;
	}

	public boolean checkForOrderNumberAndFailedStatus(String orderNumber) {
		logger.info("Entry at checkForOrderNumberAndFailedStatus(Service)");
		int result = dao.checkForOrderNumberAndFailedStatus(orderNumber);
		if (result > 0) {
			logger.info("Exit at checkForOrderNumberAndFailedStatus(Service) :- Status Exist ");
			return true;
		} else {
			logger.info("Exit at checkForOrderNumberAndFailedStatus(Service) :- Status Doesn't Exist ");
			return false;
		}
	}

	/*
	 * public boolean checkForPendingOrDeliveredOrder(int orderNumber) {
	 * logger.info("Entry at checkForPendingOrFailedOrder(Service)"); int result
	 * = dao.checkForPendingOrDeliveredOrder(orderNumber); if (result > 0) {
	 * logger.info("Exit at checkForPendingOrFailedOrder(Service)"); return
	 * true; } else {
	 * logger.info("Exit at checkForPendingOrFailedOrder(Service)"); return
	 * false; } }
	 */

	/*
	 * public boolean saveFailedStatusCommentsOfOrder(String orderNumber, String
	 * failedComments) {
	 * logger.info("Entry at saveFailedStatusCommentsOfOrder(Service)"); int
	 * result = dao.saveFailedStatusCommentsOfOrder(orderNumber,
	 * failedComments); if (result > 0) {
	 * logger.info("Exit at saveFailedStatusCommentsOfOrder(Service)"); return
	 * true; } else {
	 * logger.info("Exit at saveFailedStatusCommentsOfOrder(Service)"); return
	 * false; } }
	 */

	/*
	 * public boolean savePendingOrFailedOrderStatus(String orderNumber, String
	 * newStatusOfOrder) {
	 * logger.info("Entry at savePendingOrFailedOrderStatus(Service)"); int
	 * result = dao.savePendingOrFailedOrderStatus(orderNumber,
	 * newStatusOfOrder); if (result > 0) {
	 * logger.info("Exit at savePendingOrFailedOrderStatus(Service)"); return
	 * true; } else {
	 * logger.info("Exit at savePendingOrFailedOrderStatus(Service)"); return
	 * false; } }
	 */

	/*
	 * public boolean checkDeliveryBoyIdInDB(int deliveryBoyId) {
	 * logger.info("Entry at savePendingOrFailedOrderStatus(Service)"); int
	 * result = dao.checkDeliveryBoyIdInDB(deliveryBoyId); if (result > 0) {
	 * logger.info("Exit at checkDeliveryBoyIdInDB(Service)"); return true; }
	 * else { logger.info("Exit at checkDeliveryBoyIdInDB(Service)"); return
	 * false; } }
	 * 
	 * public List<OrderBean> filterOrdersByStatusAndTime(String date, String
	 * status) { logger.info("Entry at filterOrdersByStatusAndTime(Service)");
	 * List<OrderBean> filteredOrderList = new ArrayList<OrderBean>(); try {
	 * logger.info("Exit at filterOrdersByStatusAndTime(Service)");
	 * filteredOrderList = dao.filterOrdersByStatusAndTime(date, status); return
	 * filteredOrderList; } catch (Exception e) { logger.error("Exception :- " +
	 * e); return filteredOrderList; } }
	 * 
	 * public List<OrderBean> filterOrdersByTimeAndAssignment(String time,
	 * String assignment) {
	 * logger.info("Entry at filterOrdersByTimeAndAssignment(Service)");
	 * List<OrderBean> filteredOrderList = new ArrayList<OrderBean>(); try {
	 * logger.info("Exit at filterOrdersByTimeAndAssignment(Service)");
	 * filteredOrderList = dao.filterOrdersByTimeAndAssignment(time,
	 * assignment); return filteredOrderList; } catch (Exception e) {
	 * logger.error("Exception :- " + e); return filteredOrderList; } }
	 * 
	 * public List<OrderBean> filterOrdersByStatusAndAssignment(String status,
	 * String assignment) {
	 * logger.info("Entry at filterOrdersByStatusAndAssignment(Service)");
	 * List<OrderBean> filteredOrderList = new ArrayList<OrderBean>(); try {
	 * logger.info("Exit at filterOrdersByStatusAndAssignment(Service)");
	 * filteredOrderList = dao.filterOrdersByStatusAndAssignment(status,
	 * assignment); return filteredOrderList; } catch (Exception e) {
	 * logger.error("Exception :- " + e); return filteredOrderList; } }
	 * 
	 * public List<OrderBean> filterOrdersByStatusAndTimeAndAssignment(String
	 * status, String time, String assignment) {
	 * logger.info("Entry at filterOrdersByStatusAndTimeAndAssignment(Service)"
	 * ); List<OrderBean> filteredOrderList = new ArrayList<OrderBean>(); try {
	 * logger.info("Exit at filterOrdersByStatusAndTimeAndAssignment(Service)");
	 * filteredOrderList = dao.filterOrdersByStatusAndTimeAndAssignment(status,
	 * time, assignment); return filteredOrderList; } catch (Exception e) {
	 * logger.error("Exception :- " + e); return filteredOrderList; } }
	 */

	public List<OrderBean> filterTrackOrder(String status, String date, String assignment, String searchKey) {
		logger.info("Entry at filterTrackOrder(Service)");

		if ((status != null && status.trim().length() > 0)
				&& (status.equalsIgnoreCase(OrderNaoConstants.ORDER_STATUS_PENDING)
						|| status.equalsIgnoreCase(OrderNaoConstants.ORDER_STATUS_DELIVERED)
						|| status.equalsIgnoreCase(OrderNaoConstants.ORDER_STATUS_FAILED))) {

			if ((date != null && date.trim().length() > 0) && (date.equalsIgnoreCase(OrderNaoConstants.ORDER_DATE_TODAY)
					|| date.equalsIgnoreCase(OrderNaoConstants.ORDER_DATE_LAST_SEVEN_DAYS)
					|| date.equalsIgnoreCase(OrderNaoConstants.ORDER_DATE_THIS_MONTH)
					|| date.equalsIgnoreCase(OrderNaoConstants.ORDER_DATE_TILL_DATE))) {

				if ((assignment != null && assignment.trim().length() > 0)
						&& (assignment.equalsIgnoreCase(OrderNaoConstants.ORDER_ASSIGNED)
								|| assignment.equalsIgnoreCase(OrderNaoConstants.ORDER_UNASSIGNED))) {
					logger.info("Process request for status & date & assignment(Service)");
					// Process request for status & date & assignment
					logger.info("Exit at filterTrackOrder(Service)");
					return dao.filterOrdersByStatusAndTimeAndAssignment(status, date, assignment);
				}
				logger.info("Process request for status & date(Service)");
				// Process request for status & date
				logger.info("Exit at filterTrackOrder(Service)");
				return dao.filterOrdersByStatusAndTime(date, status);
			} else if ((assignment != null && assignment.trim().length() > 0)
					&& (assignment.equalsIgnoreCase(OrderNaoConstants.ORDER_ASSIGNED)
							|| assignment.equalsIgnoreCase(OrderNaoConstants.ORDER_UNASSIGNED))) {
				logger.info("Process request for status & assignment(Service)");
				// Process request for status & assignment
				logger.info("Exit at filterTrackOrder(Service)");
				return dao.filterOrdersByStatusAndAssignment(status, assignment);

			}
			logger.info("Process request for status(Service)");
			// Process request for status
			logger.info("Exit at filterTrackOrder(Service)");
			return dao.filterOrdersByStatus(status);

		} else if ((date != null && date.trim().length() > 0)
				&& (date.equalsIgnoreCase(OrderNaoConstants.ORDER_DATE_TODAY)
						|| date.equalsIgnoreCase(OrderNaoConstants.ORDER_DATE_LAST_SEVEN_DAYS)
						|| date.equalsIgnoreCase(OrderNaoConstants.ORDER_DATE_THIS_MONTH)
						|| date.equalsIgnoreCase(OrderNaoConstants.ORDER_DATE_TILL_DATE))) {

			if ((assignment != null && assignment.trim().length() > 0)
					&& (assignment.equalsIgnoreCase(OrderNaoConstants.ORDER_ASSIGNED)
							|| assignment.equalsIgnoreCase(OrderNaoConstants.ORDER_UNASSIGNED))) {
				logger.info("Process request for date & assignment(Service)");
				// Process request for date & assignment
				logger.info("Exit at filterTrackOrder(Service)");
				return dao.filterOrdersByTimeAndAssignment(date, assignment);

			}
			logger.info("Process request for date(Service)");
			// Process request for date
			logger.info("Exit at filterTrackOrder(Service)");
			return dao.filterOrdersByDate(date);

		} else if ((assignment != null && assignment.trim().length() > 0)
				&& (assignment.equalsIgnoreCase(OrderNaoConstants.ORDER_ASSIGNED)
						|| assignment.equalsIgnoreCase(OrderNaoConstants.ORDER_UNASSIGNED))) {
			logger.info("Process request for assignment(Service)");
			// process request for only assignment

			logger.info("Exit at filterTrackOrder(Service)");
			return dao.filterOrdersByAssignment(assignment);
		} else if (searchKey != null && searchKey.trim().length() > 0) {
			// this is used to process request in case of search
			logger.info("Process request for search :- " + searchKey);
			logger.info("Exit at ");
			return dao.searchTrackDelivery(searchKey);

		} else {
			// no condition is satisfied so we show default page
			logger.info("Processing default track delivery page (Service)");
			logger.info("Exit at filterTrackOrder(Service)");
			return dao.getOrderDetailsOfCustomer();
		}
	}

	public String savePendingOrDeliveredOrFailedOrder(int orderNumber, String status, String failedComments) {
		logger.info("Entry at savePendingOrDeliveredOrder(Service)");
		// check status of order(Pending,Delivered,Failed) else return
		// suspicious activity
		if ((status != null && status.trim().length() > 0)
				&& (status.equalsIgnoreCase(OrderNaoConstants.ORDER_STATUS_DELIVERED)
						|| status.equalsIgnoreCase(OrderNaoConstants.ORDER_STATUS_PENDING)
						|| status.equalsIgnoreCase(OrderNaoConstants.ORDER_STATUS_FAILED))) {
			// Process when status is not null
			// check for status of order in DB if pending or delivered then
			// process else return suspicious activity
			// because if status is failed(it is fixed)then we can't change it
			// to pending or delivered.
			int orderStatus = dao.checkForPendingOrDeliveredOrder(orderNumber);
			if (orderStatus > 0) {
				int newOrderStatus = 0;
				// if status is pending the save order status as pending in DB
				if (status.equalsIgnoreCase(OrderNaoConstants.ORDER_STATUS_PENDING)) {
					newOrderStatus = dao.savePendingOrDeliveredOrderStatus(orderNumber, status);
					logger.info("Saving Pending Or Delivered order status ");
				} else if (status.equalsIgnoreCase(OrderNaoConstants.ORDER_STATUS_DELIVERED)) {
					// if status is delivered then first check whether any
					// delivery boy is assigned to that order or not
					// if assigned then process else return "No delivery boy
					// assigned"
					int orderAssignedToDeliveryBoyStatus = dao.checkDeliveryBoyAssignmentForOrder(orderNumber);
					if (orderAssignedToDeliveryBoyStatus > 0) {
						logger.info("Saving Failed order status ");
						newOrderStatus = dao.savePendingOrDeliveredOrderStatus(orderNumber, status);
					} else {
						logger.info("No Delivery Boy assigned to order");
						return OrderNaoConstants.DELIVERY_BOY_NOT_ASSIGNED;
					}
				} else if (status.equalsIgnoreCase(OrderNaoConstants.ORDER_STATUS_FAILED)) {
					// if status is failed then save failed as order status in
					// DB
					newOrderStatus = dao.saveFailedStatusCommentsOfOrder(orderNumber, failedComments);
					logger.info("Saving Failed order status ");
				}

				if (newOrderStatus > 0) {
					logger.info("Exit at savePendingOrDeliveredOrder(Service) :Success");
					return OrderNaoConstants.RETURN_STATUS_SUCCESS;
				} else {
					logger.info("Exit at savePendingOrDeliveredOrder(Service) :Error");
					return OrderNaoConstants.RETURN_STATUS_ERROR;
				}
			} else {
				logger.info("Exit at savePendingOrDeliveredOrder(Service) :SuspiciousActivity");
				return OrderNaoConstants.RETURN_STATUS_SUSPICIOUS_ACTIVITY;
			}

		} else {
			logger.info("Exit at savePendingOrDeliveredOrder(Service) :SuspiciousActivity");
			return OrderNaoConstants.RETURN_STATUS_SUSPICIOUS_ACTIVITY;
		}
	}

	public String deliveryBoyOrderAssignment(int deliveryBoyId, int orderNumber) {
		logger.info("Entry at deliveryBoyOrderAssignment(Service) ");
		// here we check for id of delivery boy in db(for suspicious activity
		// i.e it is used to check if someone try to assign manager to a
		// particular order)
		int deliveryBoyStatus = dao.checkDeliveryBoyIdInDB(deliveryBoyId);
		if (deliveryBoyStatus > 0) {
			int deliveryBoysUpdate = dao.updateDeliveryBoyInOrdersTable(deliveryBoyId, orderNumber);
			if (deliveryBoysUpdate > 0) {
				logger.info("Exit at deliveryBoyOrderAssignment(Service) :success ");
				return OrderNaoConstants.RETURN_STATUS_SUCCESS;
			} else {
				logger.info("Exit at deliveryBoyOrderAssignment(Service) :error");
				return OrderNaoConstants.RETURN_STATUS_ERROR;
			}
		} else {
			logger.info("Exit at deliveryBoyOrderAssignment(Service) :suspicious activity");
			return OrderNaoConstants.RETURN_STATUS_SUSPICIOUS_ACTIVITY;
		}
	}

	public DeliveryBoyPaymentBean getDeliveryBoyPaymentDetails(int deliveryBoyId) {
		logger.info("Entry at getDeliveryBoyPaymentDetails(Service)");
		DeliveryBoyPaymentBean paymentBean = new DeliveryBoyPaymentBean();

		try {
			dao.getDeliveryBoyPaymentDetailsFromDailyTransactionTable(deliveryBoyId, paymentBean);
		} catch (Exception e) {
			logger.error("Exception :- " + e.getMessage());
		} finally {
			try {
				dao.getDeliveryBoyPaymentDetailsFromOrdersTable(deliveryBoyId, paymentBean);
			} catch (Exception e) {
				logger.error("Exception :- " + e);
			}
		}
		logger.info("Exit at getDeliveryBoyPaymentDetails(Service)");
		return paymentBean;

	}

	public boolean checkDeliveryBoy(int deliveryBoyId) {
		int status = 0;
		try {
			status = dao.checkDeliveryBoyIdInDB(deliveryBoyId);
		} catch (DataAccessException e) {
			logger.error("Exception :- " + e.getMessage());
		}
		if (status > 0) {
			return true;
		} else {
			return false;
		}
	}

	public boolean updateDeliveryBoyMoneyProvided(int deliveryBoyId, double moneyProvidedInMorning) {
		logger.info("Entry at updateDeliveryBoyMoneyProvided(Service)");
		boolean returnStatus = false;
		try {
			// here we check for current date entry of money provided for a user
			int currentDateEntry = dao.checkForCurrentDateEntryOfMoneyProvided(deliveryBoyId);
			if (currentDateEntry > 0) {
				logger.info("Current Date Entry :- True ::: Updating Money provided");
				// if entry is found in DB(i.e it is greater than zero) then we
				// update entry
				int status = dao.updateDeliveryBoyMoneyProvided(deliveryBoyId, moneyProvidedInMorning);
				if (status > 0) {
					// status is greater than zero i.e entry updated in success
					// so
					// we return true
					returnStatus = true;
				}
			} else {
				logger.info("Current Date Entry :- False ::: Inserting Current Date Entry ");
				// if entry not found in DB then we insert new entry
				int status = dao.insertCurrentDateEntryForMoneyProvidedToDeliveryBoy(deliveryBoyId,
						moneyProvidedInMorning);
				if (status > 0) {
					// status is greater than zero i.e entry updated is success
					// so
					// we return true
					returnStatus = true;
				}
			}
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		logger.info("Exit at updateDeliveryBoyMoneyProvided(Service)");
		return returnStatus;
	}

	/**
	 * @author shubham sharma
	 * @date 29-Oct-2017
	 * @time 9:54:48 PM
	 * @description Here we fetch sum of money provided to delivery boy(today)
	 *              and sum of service charge & we add both sum's
	 * @return total money to be collected(sum of money provided in morning &
	 *         service charge of current date)
	 */
	public double getTotalMoneyToBeCollected() {
		logger.info("Entry at getTotalMoneyToBeCollected(Service)");
		double totalMoneyToBeCollected = 0;
		double totalMoneyProvided = 0;
		double totalServiceChargeToCollect = 0;
		try {
			totalMoneyProvided = dao.getTotalMoneyProvided();
		} catch (Exception e) {
			logger.error("Exception :- " + e.getMessage());
		} finally {
			try {
				totalServiceChargeToCollect = dao.getTotalServiceCharge();
			} catch (Exception e2) {
				logger.error("Exception :- " + e2.getMessage());
			}
		}
		totalMoneyToBeCollected = (totalMoneyProvided + totalServiceChargeToCollect);
		logger.info("total money provided :- " + totalMoneyProvided + " + total service charge to collect :- "
				+ totalServiceChargeToCollect + " = " + totalMoneyToBeCollected + "(total Sum)");
		logger.info("Exit at getTotalMoneyToBeCollected(Service)");
		return totalMoneyToBeCollected;
	}

	/**
	 * @author shubham sharma
	 * @date 29-Oct-2017
	 * @time 11:49:06 PM
	 * @description this method return orders assigned to delivery boy
	 * @return list of order bean that contains orders assigned to delivery boy
	 */
	public List<OrderBean> getDeliveryBoyTripDetails(int deliveryBoyId) {
		List<OrderBean> deliveryBoyTripList = new ArrayList<OrderBean>();
		try {
			deliveryBoyTripList = dao.getDeliveryBoyTripDetails(deliveryBoyId);
		} catch (Exception e) {
			logger.error("Exception :- ", e.getMessage());
		}
		return deliveryBoyTripList;
	}

	/**
	 * @author shubham sharma
	 * @date 30-Oct-2017
	 * @time 5:55:00 PM
	 * @description it will update the money submitted by delivery boy
	 * @return updated money status
	 */
	public boolean updateMoneySubmittedByDeliveryBoy(int deliveryBoyId, String comments, double moneyCollected) {
		logger.info("Entry at updateMoneySubmittedByDeliveryBoy");
		int submittedMoneyStatus = 0;
		try {
			int currentDateEntry = dao.checkForCurrentDateEntryOfMoneyProvided(deliveryBoyId);
			if (currentDateEntry > 0) {
				logger.info("Delivery Boy exist in DB : Updating money submitted by delivery boy");
				submittedMoneyStatus = dao.updateMoneySubmittedByDeliveryBoy(deliveryBoyId, comments, moneyCollected);
			} else {
				logger.info("Delivery Boy doesn't exist in DB : inserting current date entry and money collected");
				submittedMoneyStatus = dao.insertCurrentDateEntryForDeliveryBoy(deliveryBoyId, moneyCollected,
						comments);
			}
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		if (submittedMoneyStatus > 0) {
			logger.info("Exit at updateMoneySubmittedByDeliveryBoy");
			return true;
		} else {
			logger.info("Exit at updateMoneySubmittedByDeliveryBoy");
			return false;
		}
	}

	/**
	 * @author shubham sharma
	 * @date 30-Oct-2017
	 * @time 6:37:13 PM
	 * @description this method will fetch total money submitted/collected
	 * @return total money collected
	 */
	public double getTotalMoneyCollected() {
		logger.info("Entry at getTotalMoneyCollected()");
		double totalMoneyCollected = 0;
		try {
			totalMoneyCollected = dao.getTotalMoneyCollected();
		} catch (Exception e) {
			logger.error("Exception :- " + e.getMessage());
		}
		logger.info("Exit at getTotalMoneyCollected() totalMoneyCollected : " + totalMoneyCollected);
		return totalMoneyCollected;
	}

	public List<OrderBean> getDeliveryBoyTripMoreDetails(int orderNumber, int deliveryBoyId) {
		List<OrderBean> deliveryBoyTripList = new ArrayList<OrderBean>();
		try {
			deliveryBoyTripList = dao.getDeliveryBoyTripMoreDetails(orderNumber, deliveryBoyId);
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		return deliveryBoyTripList;
	}

	public int getTotalOrderCountOfCurrentDate() {
		logger.info("Entry at getTotalOrderCountOfCurrentDate()");
		int totalOrderCountOfCurrentDate = 0;
		try {
			totalOrderCountOfCurrentDate = dao.getTotalOrderCountOfCurrentDate();
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		logger.info("Exit at getTotalOrderCountOfCurrentDate()");
		return totalOrderCountOfCurrentDate;
	}

	public int getSuccessfullOrderCountOfCurrentDate() {
		logger.info("Entry at getSuccessfullOrderCountOfCurrentDate()");
		int successfullOrderCountOfCurrentDate = 0;
		try {
			successfullOrderCountOfCurrentDate = dao.getSuccessfullOrderCountOfCurrentDate();
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		logger.info("Exit at getSuccessfullOrderCountOfCurrentDate()");
		return successfullOrderCountOfCurrentDate;
	}

	public int getFailedOrderCountOfCurrentDate() {
		logger.info("Entry at getFailedOrderCountOfCurrentDate()");
		int failedOrderCountOfCurrentDate = 0;
		try {
			failedOrderCountOfCurrentDate = dao.getFailedOrderCountOfCurrentDate();
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		logger.info("Exit at getFailedOrderCountOfCurrentDate()");
		return failedOrderCountOfCurrentDate;
	}

	public int getTotalOrderCountOfWeek() {
		logger.info("Entry at getTotalOrderCountOfWeek()");
		int totalOrderCountOfWeek = 0;
		try {
			totalOrderCountOfWeek = dao.getTotalOrderCountOfWeek();
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		logger.info("Exit at getTotalOrderCountOfWeek()");
		return totalOrderCountOfWeek;
	}

	public int getSuccessfullOrderCountOfWeek() {
		logger.info("Entry at getSuccessfullOrderCountOfWeek()");
		int successfullOrderCountOfWeek = 0;
		try {
			successfullOrderCountOfWeek = dao.getSuccessfullOrderCountOfWeek();
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		logger.info("Exit at getSuccessfullOrderCountOfWeek()");
		return successfullOrderCountOfWeek;
	}

	public int getFailedOrderCountOfWeek() {
		logger.info("Entry at getFailedOrderCountOfWeek()");
		int failedOrderCountOfWeek = 0;
		try {
			failedOrderCountOfWeek = dao.getFailedOrderCountOfWeek();
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		logger.info("Exit at getFailedOrderCountOfWeek()");
		return failedOrderCountOfWeek;
	}

	public int getTotalOrderCountOfMonth(int selectedMonth, int selectedYear) {
		logger.info("Entry at getTotalOrderCountOfMonth()");
		int totalOrderCountOfMonth = 0;
		try {
			totalOrderCountOfMonth = dao.getTotalOrderCountOfMonth(selectedMonth, selectedYear);
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		logger.info("Exit at getTotalOrderCountOfMonth()");
		return totalOrderCountOfMonth;
	}

	public int getSuccessfullOrderCountOfMonth(int selectedMonth, int selectedYear) {
		logger.info("Entry at getSuccessfullOrderCountOfMonth()");
		int successfullOrderCountOfMonth = 0;
		try {
			successfullOrderCountOfMonth = dao.getSuccessfullOrderCountOfMonth(selectedMonth, selectedYear);
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		logger.info("Exit at getSuccessfullOrderCountOfMonth()");
		return successfullOrderCountOfMonth;
	}

	public int getFailedOrderCountOfMonth(int selectedMonth, int selectedYear) {
		logger.info("Entry at getFailedOrderCountOfMonth()");
		int failedOrderCountOfMonth = 0;
		try {
			failedOrderCountOfMonth = dao.getFailedOrderCountOfMonth(selectedMonth, selectedYear);
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		logger.info("Exit at getFailedOrderCountOfMonth()");
		return failedOrderCountOfMonth;
	}

	public List<OrderBean> getMoreDetailsOfOrderForReport(int forDate) {
		logger.info("Entry at getMoreDetailsOfOrderForReport()");
		List<OrderBean> moreDetailsOfOrderListForReport = null;
		try {
			if (forDate == OrderNaoConstants.FOR_DAILY_TOTAL_ORDER_REPORT) {
				logger.info("FOR_DAILY_TOTAL_ORDER_REPORT");
				moreDetailsOfOrderListForReport = dao.getMoreDetailsOfOrderForDailyTotalOrder();
			} else if (forDate == OrderNaoConstants.FOR_DAILY_SUCCESSFULL_ORDER_REPORT) {
				logger.info("FOR_DAILY_SUCCESSFULL_ORDER_REPORT");
				moreDetailsOfOrderListForReport = dao.getMoreDetailsOfOrderForDailySuccessfullOrder();
			} else if (forDate == OrderNaoConstants.FOR_DAILY_FAILED_ORDER_REPORT) {
				logger.info("FOR_DAILY_FAILED_ORDER_REPORT");
				moreDetailsOfOrderListForReport = dao.getMoreDetailsOfOrderForDailyFailedOrder();
			} else if (forDate == OrderNaoConstants.FOR_WEEKLY_TOTAL_ORDER_REPORT) {
				logger.info("FOR_WEEKLY_TOTAL_ORDER_REPORT");
				moreDetailsOfOrderListForReport = dao.getMoreDetailsOfOrderForWeeklyTotalOrder();
			} else if (forDate == OrderNaoConstants.FOR_WEEKLY_SUCCESSFULL_ORDER_REPORT) {
				logger.info("FOR_WEEKLY_SUCCESSFULL_ORDER_REPORT");
				moreDetailsOfOrderListForReport = dao.getMoreDetailsOfOrderForWeeklySuccessfullOrder();
			} else if (forDate == OrderNaoConstants.FOR_WEEKLY_FAILED_ORDER_REPORT) {
				logger.info("FOR_WEEKLY_FAILED_ORDER_REPORT");
				moreDetailsOfOrderListForReport = dao.getMoreDetailsOfOrderForWeeklyFailedOrder();
			}
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		logger.info("Exit at getMoreDetailsOfOrderForReport()");
		return moreDetailsOfOrderListForReport;
	}

	public List<OrderBean> getMonthlyOrderDetailsForReport(int forDate, int selectedYear, int selectedMonth) {
		logger.info("Entry at getMonthlyOrderDetailsForReport()");
		List<OrderBean> monthlyOrderDetaisForReport = null;
		try {
			if (forDate == OrderNaoConstants.FOR_MONTHLY_TOTAL_ORDER_REPORT) {
				logger.info("FOR_MONTHLY_TOTAL_ORDER_REPORT");
				monthlyOrderDetaisForReport = dao.getMoreDetailsOfOrderForMonthlyTotalOrder(selectedYear,
						selectedMonth);
			} else if (forDate == OrderNaoConstants.FOR_MONTHLY_SUCCESSFULL_ORDER_REPORT) {
				logger.info("FOR_MONTHLY_SUCCESSFULL_ORDER_REPORT");
				monthlyOrderDetaisForReport = dao.getMoreDetailsOfOrderForMonthlySuccessfullOrder(selectedYear,
						selectedMonth);
			} else if (forDate == OrderNaoConstants.FOR_MONTHLY_FAILED_ORDER_REPORT) {
				logger.info("FOR_MONTHLY_FAILED_ORDER_REPORT");
				monthlyOrderDetaisForReport = dao.getMoreDetailsOfOrderForMonthlyFailedOrder(selectedYear,
						selectedMonth);
			}
		} catch (Exception e) {
			logger.error("Exception :- ", e);
		}
		logger.info("Exit at getMonthlyOrderDetailsForReport()");
		return monthlyOrderDetaisForReport;
	}

	public boolean checkForPhoneNumber(String contactNumber) {
		logger.info("Entry at checkForPhoneNumber");
		boolean status = false;
		try {
			int result = dao.checkForPhoneNumber(contactNumber);
			logger.info("checkForPhoneNumber :- " + result);
			if (result > 0) {
				status = true;
			} else {
				status = false;
			}
			logger.info("Exit at checkForPhoneNumber");
			return status;
		} catch (Exception e) {
			logger.error("Exception ", e);
			return true;
		}
	}

	public String saveProductPrice(int orderNumber, double productPrice) {
		logger.info("Entry at saveProductPrice");
		if (productPrice > 0) {
			try {
				int productPriceStatus = dao.saveProductPrice(orderNumber, productPrice);

				if (productPriceStatus > 0) {
					// after saving product price calculate total amount of
					// order
					// which is sum of product charge & service charge(i.e fetch
					// from DB)
					double totalAmount = dao.getTotalAmountOfOrder(orderNumber);
					if (totalAmount > 0) {
						// save/update total amount in DB corrosponding to order
						int status = dao.updateTotalAmountOfOrder(totalAmount, orderNumber);
					}
					logger.info("Exit at saveProductPrice");
					return OrderNaoConstants.RETURN_STATUS_SUCCESS;
				} else {
					logger.info("Exit at saveProductPrice");
					return OrderNaoConstants.RETURN_STATUS_SUSPICIOUS_ACTIVITY;
				}

			} catch (Exception e) {
				logger.error("Exception :- " + e);
				return OrderNaoConstants.RETURN_STATUS_ERROR;
			}
		} else {
			logger.info("Exit at saveProductPrice");
			return OrderNaoConstants.RETURN_STATUS_PRODUCT_PRICE_LESS_THAN_ZERO;
		}
	}

}
