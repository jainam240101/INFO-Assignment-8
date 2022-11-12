function sendSuccessResponse(res, data, message = "Success", message_data) {
  res.status(200).json({
    data,
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
    error: errors,
  });
}


export { sendSuccessResponse, sendErrorResponse };
