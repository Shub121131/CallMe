package com.ordernao.bean;

public class DeliveryBoyPaymentBean {
	private int deliveryBoyId;
	private double totalDistanceTravelled;
	private double totalServiceChargeToCollect;
	private double totalMoneyProvidedInMorning;
	private double moneyCollected;
	
	

	public double getMoneyCollected() {
		return moneyCollected;
	}

	public void setMoneyCollected(double moneyCollected) {
		this.moneyCollected = moneyCollected;
	}

	public double getTotalMoneyProvidedInMorning() {
		return totalMoneyProvidedInMorning;
	}

	public void setTotalMoneyProvidedInMorning(double totalMoneyProvidedInMorning) {
		this.totalMoneyProvidedInMorning = totalMoneyProvidedInMorning;
	}

	public int getDeliveryBoyId() {
		return deliveryBoyId;
	}

	public void setDeliveryBoyId(int deliveryBoyId) {
		this.deliveryBoyId = deliveryBoyId;
	}

	public double getTotalDistanceTravelled() {
		return totalDistanceTravelled;
	}

	public void setTotalDistanceTravelled(double totalDistanceTravelled) {
		this.totalDistanceTravelled = totalDistanceTravelled;
	}

	public double getTotalServiceChargeToCollect() {
		return totalServiceChargeToCollect;
	}

	public void setTotalServiceChargeToCollect(double totalServiceChargeToCollect) {
		this.totalServiceChargeToCollect = totalServiceChargeToCollect;
	}


}
