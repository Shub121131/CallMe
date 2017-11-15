package com.ordernao.bean;

import java.util.Date;

public class OrderBean {
	private int customerId;
	private String customerFirstName;
	private String customerLastName;
	private String customerPhone;
	private String customerAddress;
	private String userFirstName;
	private String userLastName;
	private int totalDistance;
	private double serviceCharge;
	private double totalAmount;
	private boolean newCustomer;
	private String comments;
	private String commentStatus;
	private int totalNumberOfOrders;
	private String itemName;
	private String orderPickedFrom;
	private String orderDeliveredAt;
	private Date orderDate;
	private int orderNumber;
	private String orderStatus;
	private int deliveryBoyId;
	private String deliveryBoyFirstName;
	private String deliveryBoyLastName;
	private String deliveryBoyPhone;
	private int orderCount;
	private double productCharge;

	public double getProductCharge() {
		return productCharge;
	}

	public void setProductCharge(double productCharge) {
		this.productCharge = productCharge;
	}

	public int getOrderCount() {
		return orderCount;
	}

	public void setOrderCount(int orderCount) {
		this.orderCount = orderCount;
	}

	public int getDeliveryBoyId() {
		return deliveryBoyId;
	}

	public void setDeliveryBoyId(int deliveryBoyId) {
		this.deliveryBoyId = deliveryBoyId;
	}

	public String getDeliveryBoyFirstName() {
		return deliveryBoyFirstName;
	}

	public void setDeliveryBoyFirstName(String deliveryBoyFirstName) {
		if(deliveryBoyFirstName==null){
			this.deliveryBoyFirstName="";
		}else{
			this.deliveryBoyFirstName = deliveryBoyFirstName;
		}
	}

	public String getDeliveryBoyLastName() {
		return deliveryBoyLastName;
	}

	public void setDeliveryBoyLastName(String deliveryBoyLastName) {
		if(deliveryBoyLastName==null){
			this.deliveryBoyLastName="";
		}else{
			this.deliveryBoyLastName = deliveryBoyLastName;
		}
	}

	public String getDeliveryBoyPhone() {
		return deliveryBoyPhone;
	}

	public void setDeliveryBoyPhone(String deliveryBoyPhone) {
		this.deliveryBoyPhone = deliveryBoyPhone;
	}

	public Date getOrderDate() {
		return orderDate;
	}

	public void setOrderDate(Date orderDate) {
		this.orderDate = orderDate;
	}

	public int getOrderNumber() {
		return orderNumber;
	}

	public void setOrderNumber(int orderNumber) {
		this.orderNumber = orderNumber;
	}

	public String getOrderStatus() {
		return orderStatus;
	}

	public void setOrderStatus(String orderStatus) {
		this.orderStatus = orderStatus;
	}

	public String getItemName() {
		return itemName;
	}

	public void setItemName(String itemName) {
		this.itemName = itemName;
	}

	public String getOrderPickedFrom() {
		return orderPickedFrom;
	}

	public void setOrderPickedFrom(String orderPickedFrom) {
		this.orderPickedFrom = orderPickedFrom;
	}

	public String getOrderDeliveredAt() {
		return orderDeliveredAt;
	}

	public void setOrderDeliveredAt(String orderDeliveredAt) {
		this.orderDeliveredAt = orderDeliveredAt;
	}

	public int getTotalNumberOfOrders() {
		return totalNumberOfOrders;
	}

	public void setTotalNumberOfOrders(int totalNumberOfOrders) {
		this.totalNumberOfOrders = totalNumberOfOrders;
	}

	public String getComments() {
		return comments;
	}

	public void setComments(String comments) {
		this.comments = comments;
	}

	public String getCommentStatus() {
		return commentStatus;
	}

	public void setCommentStatus(String commentStatus) {
		this.commentStatus = commentStatus;
	}

	public boolean isNewCustomer() {
		return newCustomer;
	}

	public void setNewCustomer(boolean newCustomer) {
		this.newCustomer = newCustomer;
	}

	public int getCustomerId() {
		return customerId;
	}

	public void setCustomerId(int customerId) {
		this.customerId = customerId;
	}

	public double getTotalAmount() {
		return totalAmount;
	}

	public void setTotalAmount(double totalAmount) {
		this.totalAmount = totalAmount;
	}

	public double getServiceCharge() {
		return serviceCharge;
	}

	public void setServiceCharge(double serviceCharge) {
		this.serviceCharge = serviceCharge;
	}

	public int getTotalDistance() {
		return totalDistance;
	}

	public void setTotalDistance(int totalDistance) {
		this.totalDistance = totalDistance;
	}

	public String getCustomerFirstName() {
		return customerFirstName;
	}

	public void setCustomerFirstName(String customerFirstName) {
		this.customerFirstName = customerFirstName;
	}

	public String getCustomerLastName() {
		return customerLastName;
	}

	public void setCustomerLastName(String customerLastName) {
		this.customerLastName = customerLastName;
	}

	public String getCustomerPhone() {
		return customerPhone;
	}

	public void setCustomerPhone(String customerPhone) {
		this.customerPhone = customerPhone;
	}

	public String getCustomerAddress() {
		return customerAddress;
	}

	public void setCustomerAddress(String customerAddress) {
		this.customerAddress = customerAddress;
	}

	public String getUserFirstName() {
		return userFirstName;
	}

	public void setUserFirstName(String userFirstName) {
		this.userFirstName = userFirstName;
	}

	public String getUserLastName() {
		return userLastName;
	}

	public void setUserLastName(String userLastName) {
		this.userLastName = userLastName;
	}
public String toString(){
	StringBuilder sb = new StringBuilder();
	sb.append("customerId");
	sb.append(":");
	sb.append(customerId);
	sb.append(",");
	
	sb.append("customerFirstName");
	sb.append(":");
	sb.append(customerFirstName);
	sb.append(",");
	
	sb.append("customerLastName");
	sb.append(":");
	sb.append(customerLastName);
	sb.append(",");
	
	sb.append("customerPhone");
	sb.append(":");
	sb.append(customerPhone);
	sb.append(",");
	
	sb.append("customerAddress");
	sb.append(":");
	sb.append(customerAddress);
	sb.append(",");
	
	sb.append("userFirstName");
	sb.append(":");
	sb.append(userFirstName);
	sb.append(",");
	
	sb.append("userLastName");
	sb.append(":");
	sb.append(userLastName);
	sb.append(",");
	
	sb.append("totalDistance");
	sb.append(":");
	sb.append(totalDistance);
	sb.append(",");
	
	sb.append("serviceCharge");
	sb.append(":");
	sb.append(serviceCharge);
	sb.append(",");
	
	sb.append("totalAmount");
	sb.append(":");
	sb.append(totalAmount);
	sb.append(",");
	
	sb.append("newCustomer");
	sb.append(":");
	sb.append(newCustomer);
	sb.append(",");
	
	sb.append("comments");
	sb.append(":");
	sb.append(comments);
	sb.append(",");
	
	sb.append("commentStatus");
	sb.append(":");
	sb.append(commentStatus);
	sb.append(",");
	
	sb.append("totalNumberOfOrders");
	sb.append(":");
	sb.append(totalNumberOfOrders);
	sb.append(",");
	
	sb.append("itemName");
	sb.append(":");
	sb.append(itemName);
	sb.append(",");
	
	sb.append("orderPickedFrom");
	sb.append(":");
	sb.append(orderPickedFrom);
	sb.append(",");
	
	sb.append("orderDeliveredAt");
	sb.append(":");
	sb.append(orderDeliveredAt);
	sb.append(",");
	
	sb.append("orderDate");
	sb.append(":");
	sb.append(orderDate);
	sb.append(",");
	
	sb.append("orderNumber");
	sb.append(":");
	sb.append(orderNumber);
	sb.append(",");
	
	sb.append("orderStatus");
	sb.append(":");
	sb.append(orderStatus);
	sb.append(",");
	
	sb.append("deliveryBoyId");
	sb.append(":");
	sb.append(deliveryBoyId);
	sb.append(",");
	
	sb.append("deliveryBoyFirstName");
	sb.append(":");
	sb.append(deliveryBoyFirstName);
	sb.append(",");
	
	sb.append("deliveryBoyLastName");
	sb.append(":");
	sb.append(deliveryBoyLastName);
	sb.append(",");
	
	sb.append("deliveryBoyPhone");
	sb.append(":");
	sb.append(deliveryBoyPhone);
	sb.append(",");
	
	sb.append("orderCount");
	sb.append(":");
	sb.append(orderCount);
	sb.append(",");
	
	sb.append("productCharge");
	sb.append(":");
	sb.append(productCharge);
	return sb.toString();
}
}
