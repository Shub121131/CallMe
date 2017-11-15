package com.ordernao.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.jdbc.core.RowMapper;

import com.ordernao.bean.OrderBean;
import com.ordernao.utility.OrderNaoConstants;

public class TrackOrderRowMapper implements RowMapper<OrderBean> {
	@Override
	public OrderBean mapRow(ResultSet rs, int rowNum) throws SQLException {
		OrderBean orderBean = new OrderBean();
		orderBean.setOrderCount(rs.getInt(OrderNaoConstants.COLUMN_NAME_ORDER_COUNT));
		orderBean.setCustomerPhone(rs.getString(OrderNaoConstants.COLUMN_NAME_CUSTOMER_PHONE));
		orderBean.setOrderNumber(rs.getInt(OrderNaoConstants.COLUMN_NAME_ORDER_NUMBER));
		orderBean.setOrderDate(rs.getDate(OrderNaoConstants.COLUMN_NAME_ORDER_DATE));
		orderBean.setOrderStatus(rs.getString(OrderNaoConstants.COLUMN_NAME_ORDER_STATUS));
		orderBean.setOrderPickedFrom(rs.getString(OrderNaoConstants.COLUMN_NAME_PICKUP_POINT));
		orderBean.setOrderDeliveredAt(rs.getString(OrderNaoConstants.COLUMN_NAME_DELIVERY_POINT));
		orderBean.setItemName(rs.getString(OrderNaoConstants.COLUMN_NAME_ITEM_NAME));
		orderBean.setTotalDistance(rs.getInt(OrderNaoConstants.COLUMN_NAME_TOTAL_DISTANCE));
		orderBean.setProductCharge(rs.getDouble(OrderNaoConstants.COLUMN_NAME_PRODUCT_CHARGE));
		orderBean.setServiceCharge(rs.getDouble(OrderNaoConstants.COLUMN_NAME_SERVICE_CHARGE));
		orderBean.setDeliveryBoyId(rs.getInt(OrderNaoConstants.COLUMN_NAME_USERID));
		orderBean.setDeliveryBoyFirstName(rs.getString(OrderNaoConstants.COLUMN_NAME_USER_FIRSTNAME));
		orderBean.setDeliveryBoyLastName(rs.getString(OrderNaoConstants.COLUMN_NAME_USER_LASTNAME));
		orderBean.setDeliveryBoyPhone(rs.getString(OrderNaoConstants.COLUMN_NAME_USER_PHONE));

		return orderBean;
	}
}
