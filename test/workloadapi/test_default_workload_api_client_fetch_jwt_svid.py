import pytest
import datetime
from calendar import timegm
from cryptography.hazmat.primitives.asymmetric import rsa
from test.svid.test_utils import get_keys_pems, create_jwt

from pyspiffe.proto.spiffe import workload_pb2
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient


rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_key_pem, public_rsa_key_pem = get_keys_pems(rsa_key)


def test_fetch_jwt_svid_success(mocker):
    client = DefaultWorkloadApiClient('unix:///dummy.path')
    spiffe_id = 'spiffe://test.orgcom/my_service'
    audience = ['spire', 'test', 'valid']
    jwt_svid = create_jwt(rsa_key_pem, 'kid1', "RS256", audience, spiffe_id)

    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.JWTSVIDResponse(
                    svids=[
                        workload_pb2.JWTSVID(
                            spiffe_id=spiffe_id,
                            svid=jwt_svid,
                        )
                    ]
                )
            ]
        )
    )

    svid = client.fetch_jwt_svid()

    assert svid.spiffeId == SpiffeId.parse(spiffe_id)
    assert svid.token == jwt_svid
    assert svid.claims['aud'] == audience
    utc_time = timegm(datetime.datetime.utcnow().utctimetuple())
    assert int(svid.expiry) > utc_time
