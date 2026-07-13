import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  vus: 20,
  duration: "30s",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<75"]
  }
};

export default function () {
  const res = http.get("http://localhost:8080/live");
  check(res, { "live is ok": (r) => r.status === 200 });
  sleep(1);
}
