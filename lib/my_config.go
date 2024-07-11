package nuclei

func WithTimeout(timeout int) NucleiSDKOptions {
	return func(e *NucleiEngine) error {
		e.opts.Timeout = timeout
		return nil
	}
}
