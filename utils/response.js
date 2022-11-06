function sendSuccessResponse(res, data, message = "Success", message_data) {
  res.status(200).json({
    data,
    status: true,
    message,
    message_data,
  });
}

function sendErrorResponse(
  res,
  errors,
  message = "Something Went Wrong",
  status = 406
) {
  res.status(status).json({
    data: errors,
    status: false,
    error: errors,
  });
}

function sendEmptyResponse(res, data) {
  res.status(204).json({
    data,
    status: false,
    message: "No Data",
  });
}

export { sendSuccessResponse, sendEmptyResponse, sendErrorResponse };
