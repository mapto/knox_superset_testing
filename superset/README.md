Currently the Superset side of the KnoxSSO-Superset integration is implemented via three files:

* knox_auth.py is the file that contains the bulk of the logic.
* config.py - from the above file one can see which particular parameters are being used.
* __init__.py - the only addition is the attachment of a `before_request` handler for cookie authentication. A possible alternative approach is discussed in an [issue](https://github.com/apache/incubator-superset/issues/7024) on Superset GitHub.
