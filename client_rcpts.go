package smtp

//GetRcpts Get success rcpt to list
func (c *Client) GetRcpts() []string {
	return c.rcpts
}
