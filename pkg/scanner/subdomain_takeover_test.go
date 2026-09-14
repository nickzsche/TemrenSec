package scanner

import "testing"

func TestFingerprintTakeover(t *testing.T) {
	cases := []struct {
		body    string
		service string
	}{
		{"<html>There isn't a GitHub Pages site here.</html>", "GitHub Pages"},
		{"<Error><Code>NoSuchBucket</Code></Error>", "AWS S3"},
		{"The specified bucket does not exist", "AWS S3"},
		{"<h1>No such app</h1>", "Heroku"},
		{"There's nothing here, yet.", "Heroku"},
		{"404 Web Site not found.", "Azure"},
		{"Fastly error: unknown domain", "Fastly"},
		{"Not Found", "Netlify"},
		{"Sorry, this shop is currently unavailable.", "Shopify"},
		{"200 OK nothing to see here", ""},
	}
	for _, c := range cases {
		got, ok := fingerprintTakeover(c.body)
		if c.service == "" {
			if ok {
				t.Errorf("fingerprintTakeover(%q) = %q, true; want no match", c.body, got)
			}
			continue
		}
		if !ok || got != c.service {
			t.Errorf("fingerprintTakeover(%q) = %q, %v; want %q, true", c.body, got, ok, c.service)
		}
	}
}

func TestMatchServiceSuffix(t *testing.T) {
	cases := []struct {
		cname   string
		service string
	}{
		{"blog.foo.github.io.", "GitHub Pages"},
		{"foo.github.io", "GitHub Pages"},
		{"example.s3.amazonaws.com.", "AWS S3"},
		{"bucket.s3-website-us-east-1.amazonaws.com.", "AWS S3"},
		{"app.herokuapp.com.", "Heroku"},
		{"app.herokudns.com.", "Heroku"},
		{"app.azurewebsites.net.", "Azure"},
		{"vm.cloudapp.azure.com.", "Azure"},
		{"global.prod.fastly.net.", "Fastly"},
		{"shop.shops.myshopify.com.", "Shopify"},
		{"site.netlify.app.", "Netlify"},
		{"x.surge.sh.", "Surge"},
		{"d123.cloudfront.net.", "CloudFront"},
		{"repo.bitbucket.io.", "Bitbucket"},
		{"example.com.", ""},
		{"evilgithub.io.", ""},
	}
	for _, c := range cases {
		if got := matchServiceSuffix(c.cname); got != c.service {
			t.Errorf("matchServiceSuffix(%q) = %q; want %q", c.cname, got, c.service)
		}
	}
}
