on vuln_nextjs2

package.json add
  "scripts": {
     "dev": "next dev -H 0.0.0.0 -p 3000"
  }

docker run -it --rm -v $(pwd):/app -p3000:3000 -w /app node:18 bash
