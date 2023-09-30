let data = { visits: 0 };

exports.handler = async (event, context) => {
    data.visits += 1;
    return {
        statusCode: 200,
        body: JSON.stringify(data)
    };
};
